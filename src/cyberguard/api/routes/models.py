"""Additive model discovery and typed, model-selected prediction routes."""

import logging

from fastapi import APIRouter, Request

from cyberguard.api.dependencies import APIError
from cyberguard.core.model_schemas import (
    BoTPredictionRequest,
    ModelBatchResponse,
    ModelPredictionResponse,
    NFPredictionRequest,
    model_batch_types,
)

logger = logging.getLogger(__name__)


def model_router(settings):
    router = APIRouter(prefix="/api/v1/models", tags=["models"])
    bot_batch, nf_batch = model_batch_types(settings.max_batch_size)
    batches = {BoTPredictionRequest: bot_batch, NFPredictionRequest: nf_batch}

    def entry(request, model_id, ready=False):
        model = request.app.state.registry.entries.get(model_id)
        if model is None:
            raise APIError(404, "unknown_model", "Unknown model identifier")
        if ready and model.adapter is None:
            raise APIError(503, "model_unavailable", "Requested model is not ready")
        return model

    @router.get("")
    def models(request: Request):
        return {
            "models": [
                m.metadata() for m in request.app.state.registry.entries.values()
            ]
        }

    @router.get("/{model_id}")
    def model_info(model_id: str, request: Request):
        return entry(request, model_id).metadata()

    @router.get("/{model_id}/ready")
    def ready(model_id: str, request: Request):
        model = entry(request, model_id, ready=True)
        return {"model_id": model.model_id, "status": "ready", "model_loaded": True}

    def infer(request, model_id, payload, batch=False):
        model = entry(request, model_id, ready=True)
        expected = (
            batches[model.adapter.request_type] if batch else model.adapter.request_type
        )
        if not isinstance(payload, expected):
            raise APIError(
                422,
                "validation_error",
                "Request schema or operating mode does not match the selected model",
            )
        records = payload.records if batch else [payload.record]
        try:
            return model.predict(
                [r.model_dump() for r in records], payload.operating_mode
            )
        except Exception as exc:
            logger.error(
                "model_inference_failed model=%s error_type=%s",
                model_id,
                type(exc).__name__,
            )
            raise APIError(500, "inference_failed", "Model prediction failed") from exc

    @router.post("/{model_id}/predict", response_model=ModelPredictionResponse)
    def predict(
        model_id: str,
        payload: BoTPredictionRequest | NFPredictionRequest,
        request: Request,
    ):
        return infer(request, model_id, payload)[0]

    @router.post("/{model_id}/predict/batch", response_model=ModelBatchResponse)
    def batch(model_id: str, payload: bot_batch | nf_batch, request: Request):
        result = infer(request, model_id, payload, batch=True)
        return {"predictions": result, "count": len(result)}

    return router
