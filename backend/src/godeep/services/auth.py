"""Operator provisioning and database-backed revocable authentication."""

import re
import secrets
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from godeep.core.security import aware, hasher, token_hash, verify_password
from godeep.persistence.models import AuthSession, User, utc_now
from godeep.schemas.auth import Principal


def unauthorized():
    return HTTPException(
        401, "Invalid or expired credentials", headers={"WWW-Authenticate": "Bearer"}
    )


def create_user(factory, username: str, password: str) -> User:
    username = username.lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username):
        raise ValueError(
            "Username must contain 3-80 ASCII letters, digits, dots, dashes or underscores"
        )
    if not 15 <= len(password) <= 128:
        raise ValueError("Password must contain 15-128 characters")
    encoded = hasher.hash(password)
    try:
        with factory.begin() as session:
            user = User(username=username, password_hash=encoded)
            session.add(user)
            session.flush()
        return user
    except IntegrityError as exc:
        raise ValueError("Username already exists") from exc


def login(factory, settings, username: str, password: str) -> dict:
    now = utc_now()
    accepted = False
    with factory.begin() as session:
        user = session.scalar(
            select(User).where(User.username == username.lower()).with_for_update()
        )
        valid = verify_password(user.password_hash if user else None, password)
        locked = (
            user is not None and user.locked_until is not None and aware(user.locked_until) > now
        )
        if user is not None and user.is_active and valid and not locked:
            user.failed_attempts = 0
            user.locked_until = None
            if hasher.check_needs_rehash(user.password_hash):
                user.password_hash = hasher.hash(password)
            raw_token = secrets.token_urlsafe(32)
            expires_at = now + timedelta(seconds=settings.session_ttl_seconds)
            session.add(
                AuthSession(
                    token_digest=token_hash(raw_token), user_id=user.id, expires_at=expires_at
                )
            )
            accepted = True
        elif user is not None and user.is_active and not locked:
            if user.locked_until is not None and aware(user.locked_until) <= now:
                user.failed_attempts = 0
                user.locked_until = None
            user.failed_attempts += 1
            if user.failed_attempts >= settings.login_max_attempts:
                user.locked_until = now + timedelta(seconds=settings.login_lock_seconds)
    # Raise after transaction commit so failed-attempt accounting is retained.
    if not accepted:
        raise unauthorized()
    return {"access_token": raw_token, "token_type": "bearer", "expires_at": expires_at}


def authenticate(factory, token: str) -> Principal:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise unauthorized()
    digest = token_hash(token)
    with factory() as session:
        record = session.get(AuthSession, digest)
        if record is None or record.revoked_at is not None or aware(record.expires_at) <= utc_now():
            raise unauthorized()
        user = session.get(User, record.user_id)
        if user is None or not user.is_active:
            raise unauthorized()
        return Principal(user.id, user.username, digest)


def logout(factory, principal: Principal):
    with factory.begin() as session:
        session.execute(
            update(AuthSession)
            .where(AuthSession.token_digest == principal.token_digest)
            .values(revoked_at=utc_now())
        )


def disable_user(factory, username: str):
    with factory.begin() as session:
        user = session.scalar(
            select(User).where(User.username == username.lower()).with_for_update()
        )
        if user is None:
            raise ValueError("User not found")
        user.is_active = False
        session.execute(
            update(AuthSession).where(AuthSession.user_id == user.id).values(revoked_at=utc_now())
        )
