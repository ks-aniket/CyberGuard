"""FastAPI inference application; one trusted model load per lifespan/process."""

import asyncio
import logging
from contextlib import asynccontextmanager
from itertools import count

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from cyberguard.api.body_limit import ModelRequestBodyLimit
from cyberguard.api.dependencies import APIError
from cyberguard.api.routes.health import router as health_router
from cyberguard.api.routes.models import model_router
from cyberguard.api.routes.predictions import prediction_router
from cyberguard.api.routes.simulations import router as simulation_router
from cyberguard.core.config import PROJECT_ROOT, Settings
from cyberguard.core.logging import configure_logging
from cyberguard.inference.model_registry import BOT_ID, ModelRegistry
from cyberguard.simulation.engine import SimulationController

logger = logging.getLogger(__name__)


def create_app(settings=None):
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(application):
        configure_logging(settings.log_level)
        logger.info("application_startup service=cyberguard-api")
        try:
            application.state.registry = ModelRegistry(settings, PROJECT_ROOT)
            application.state.registry.load()
            legacy = application.state.registry.entries[BOT_ID].adapter
            application.state.detector = legacy.detector if legacy is not None else None
            application.state.simulations = SimulationController(
                application.state.registry, settings
            )
            yield
        finally:
            if application.state.simulations is not None:
                await asyncio.to_thread(application.state.simulations.close)
            application.state.detector = None
            if application.state.registry is not None:
                application.state.registry.close()
            logger.info("application_shutdown service=cyberguard-api")

    application = FastAPI(
        title="CyberGuard Network Inference API",
        version="0.1.0",
        lifespan=lifespan,
        description="Experimental BoT protocol/port and NF-CSE completed-bidirectional-flow inference. Uncalibrated scores; no live packet capture. Legacy endpoints remain BoT-only.",
    )
    application.state.settings = settings
    application.state.detector = None
    application.state.registry = None
    application.state.simulations = None
    application.state.prediction_requests = count(1)

    @application.exception_handler(APIError)
    async def api_error(_request, exc):
        return JSONResponse(
            status_code=exc.status,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @application.exception_handler(RequestValidationError)
    async def invalid_request(_request, exc):
        # Omit Pydantic input/context fields, which contain submitted values.
        details = [
            {
                "location": list(error["loc"]),
                "type": error["type"],
                "message": error["msg"],
            }
            for error in exc.errors()
        ]
        logger.info("request_validation_failed errors=%d", len(details))
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Invalid request schema",
                    "details": details,
                }
            },
        )

    @application.exception_handler(HTTPException)
    async def http_error(_request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": "http_error",
                    "message": "Request could not be completed",
                }
            },
        )

    @application.exception_handler(Exception)
    async def unexpected_error(_request: Request, exc: Exception):
        logger.error("request_failed error_type=%s", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "Request could not be completed",
                }
            },
        )

    application.add_middleware(
        ModelRequestBodyLimit, maximum=settings.max_model_request_bytes
    )
    application.include_router(model_router(settings))
    application.include_router(simulation_router)
    application.include_router(health_router)
    application.include_router(prediction_router(settings))
    return application


app = create_app()


def main():
    import uvicorn

    settings = Settings.from_env()
    uvicorn.run(
        "cyberguard.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        reload=False,
    )


if __name__ == "__main__":
    main()
