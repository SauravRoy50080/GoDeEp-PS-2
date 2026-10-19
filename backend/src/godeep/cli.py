"""Trusted local operator commands. Passwords are read interactively, never as flags."""

import argparse
import getpass
import sys

from godeep.core.config import Settings
from godeep.persistence.database import build_engine, session_factory
from godeep.services.auth import create_user, disable_user
from godeep.services.cases import claim_legacy_case


def main():
    parser = argparse.ArgumentParser(description="GoDeEp local account administration")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user")
    create.add_argument("--username", required=True)
    disable = sub.add_parser("disable-user")
    disable.add_argument("--username", required=True)
    claim = sub.add_parser("claim-case")
    claim.add_argument("--case-id", required=True)
    claim.add_argument("--username", required=True)
    args = parser.parse_args()
    engine = build_engine(Settings().database_url.get_secret_value())
    factory = session_factory(engine)
    try:
        if args.command == "create-user":
            password = getpass.getpass("Password (15-128 characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise ValueError("Passwords do not match")
            user = create_user(factory, args.username, password)
            print(f"Created user {user.username} ({user.id})")
        elif args.command == "disable-user":
            disable_user(factory, args.username)
            print("User disabled and sessions revoked")
        else:
            claim_legacy_case(factory, args.case_id, args.username)
            print("Legacy case assigned with an operator audit event")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
