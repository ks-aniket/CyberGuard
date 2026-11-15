"""Synchronous inference runs in FastAPI's worker threadpool, not its event loop."""

import logging
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from cyberguard.api.dependencies import APIError, get_detector
from cyberguard.core.schemas import (
    BatchPredictionResponse,
    ModelInfoResponse,
    NetworkRecord,
    PredictionResponse,
    batch_request_type,
)
from cyberguard.inference.network_detector import NetworkDetector

logger = logging.getLogger(__name__)
Detector = Annotated[NetworkDetector, Depends(get_detector)]


def prediction_router(settings):
    router = APIRouter(prefix="/api/v1")
    batch_schema = batch_request_type(settings.max_batch_size)

    @router.get("/model/info", response_model=ModelInfoResponse)
    def model_info(detector: Detector):
        return detector.metadata()

    def infer(records, request, detector):
        count = next(request.app.state.prediction_requests)
        logger.info("prediction_request count=%d batch_size=%d", count, len(records))
        try:
            predictions = detector.predict_batch(
                [record.model_dump() for record in records]
            )
        except Exception as exc:
            # Exception messages from an estimator can contain raw feature values.
            logger.error("inference_failed error_type=%s", type(exc).__name__)
            raise APIError(
                500, "inference_failed", "Network prediction failed"
            ) from exc
        logger.info(
            "prediction_complete count=%d batch_size=%d model=%s",
            count,
            len(records),
            detector.metadata()["model"],
        )
        return [asdict(prediction) for prediction in predictions]

    @router.post("/predict", response_model=PredictionResponse)
    def predict(record: NetworkRecord, request: Request, detector: Detector):
        return infer([record], request, detector)[0]

    @router.post("/predict/batch", response_model=BatchPredictionResponse)
    def predict_batch(batch: batch_schema, request: Request, detector: Detector):
        predictions = infer(batch.records, request, detector)
        return {"predictions": predictions, "count": len(predictions)}

    return router
