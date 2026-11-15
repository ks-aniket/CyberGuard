"""Bound additive model prediction request bodies before JSON parsing, including chunks."""

from starlette.responses import JSONResponse


class ModelRequestBodyLimit:
    def __init__(self, app, maximum):
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or not scope["path"].startswith("/api/v1/models/")
        ):
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.maximum:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "code": "request_too_large",
                            "message": "Model request body exceeds configured byte limit",
                        }
                    },
                )
                return await response(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        return await self.app(scope, bounded_receive, send)
