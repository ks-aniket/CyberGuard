"""Strict JSON structure; feature values retain the fitted preprocessing contract."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, create_model

FeatureValue = StrictStr | StrictInt | None
Label = Literal["Normal", "DoS", "DDoS", "Reconnaissance"]


class NetworkRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Required fields, with explicit JSON null accepted as a missing value.
    proto: FeatureValue
    sport: FeatureValue
    dport: FeatureValue


def batch_request_type(maximum):
    # A per-app bound is reflected in both validation and its OpenAPI schema.
    return create_model(
        "BatchPredictionRequest",
        __config__=ConfigDict(extra="forbid"),
        records=(list[NetworkRecord], Field(..., min_length=1, max_length=maximum)),
    )


class PredictionResponse(BaseModel):
    prediction: Label
    probabilities: dict[Label, float] | None
    model: str
    warning: str


class BatchPredictionResponse(BaseModel):
    predictions: list[PredictionResponse]
    count: int


class ModelInfoResponse(BaseModel):
    model: str
    model_type: str
    required_features: list[str]
    supported_classes: list[Label]
    probabilities_available: bool
    artifact_sha256: str | None
    preprocessing_contract_version: str | None
    warning: str
