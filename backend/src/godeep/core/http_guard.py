"""Bounded JSON bodies and passive response headers; APK streams keep intake limits."""

import json
import re
from uuid import uuid4


class HttpGuard:
    def __init__(self, app, settings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = uuid4().hex

        async def protected_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                names = {key.lower() for key, _ in headers}
                for key, value in [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-request-id", request_id.encode()),
                ]:
                    if key not in names:
                        headers.append((key, value))
                message = {**message, "headers": headers}
            await send(message)

        async def error(status, detail):
            body = json.dumps({"detail": detail}).encode()
            await protected_send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await protected_send({"type": "http.response.body", "body": body})

        if scope["method"] in {"GET", "HEAD", "OPTIONS"}:
            return await self.app(scope, receive, protected_send)
        path = scope["path"]
        upload = bool(re.fullmatch(r"/api/v1/cases/[^/]+/samples/?", path))
        limit = (
            self.settings.max_upload_bytes
            if upload
            else self.settings.max_runtime_capture_bytes
            if path.rstrip("/").endswith("/runtime-captures")
            else self.settings.max_json_request_bytes
        )
        lengths = [value for key, value in scope["headers"] if key.lower() == b"content-length"]
        if len(lengths) > 1 or (lengths and not re.fullmatch(rb"[0-9]+", lengths[0])):
            return await error(400, "Invalid Content-Length")
        if lengths and (len(lengths[0]) > 20 or int(lengths[0]) > limit):
            return await error(413, "Request body exceeds configured bounds")
        if upload:  # Intake bounds and hashes the stream without prebuffering.
            return await self.app(scope, receive, protected_send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                return await error(413, "Request body exceeds configured bounds")
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        return await self.app(scope, replay, protected_send)
