"""Application-scoped detector injection and public API error contract."""

from fastapi import Request


class APIError(Exception):
    def __init__(self, status, code, message):
        self.status = status
        self.code = code
        self.message = message


def get_detector(request: Request):
    detector = getattr(request.app.state, "detector", None)
    if detector is None:
        raise APIError(503, "model_unavailable", "Network model is not ready")
    return detector
