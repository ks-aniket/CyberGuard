"""Liveness and model readiness without inference."""

from fastapi import APIRouter, Request

from cyberguard.api.dependencies import get_detector

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "service": "cyberguard-api"}


@router.get("/health/ready")
def ready(request: Request):
    get_detector(request)
    return {"status": "ready", "model_loaded": True}
