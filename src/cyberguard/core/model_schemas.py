"""Additive model-specific JSON contracts; legacy schemas are unchanged."""

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    create_model,
    field_validator,
)

from cyberguard.core.schemas import NetworkRecord
from cyberguard.features import nf_cse as nf

Scalar = StrictStr | StrictInt | StrictFloat


class NFCompletedFlowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    PROTOCOL: Scalar
    L4_SRC_PORT: Scalar
    L4_DST_PORT: Scalar
    IN_BYTES: Scalar
    OUT_BYTES: Scalar
    IN_PKTS: Scalar
    OUT_PKTS: Scalar

    @field_validator("PROTOCOL")
    @classmethod
    def protocol(cls, value):
        if nf.protocol_token(value) in (nf.INVALID, nf.MISSING):
            raise ValueError(
                "Expected a protocol alias or integral IP protocol byte 0..255"
            )
        return value

    @field_validator("L4_SRC_PORT", "L4_DST_PORT")
    @classmethod
    def port(cls, value):
        parsed = nf.integer_token(value, 65535, port=True)
        if parsed not in (nf.SENTINEL,) and parsed < 0:
            raise ValueError(
                "Expected an integral port 0..65535 or explicit -/-1 sentinel"
            )
        return value

    @field_validator("IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS")
    @classmethod
    def counter(cls, value):
        if nf.integer_token(value, nf.MAX_COUNTER) < 0:
            raise ValueError(
                "Expected a finite nonnegative integral counter <= 9007199254740991"
            )
        return value


class BoTPredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record: NetworkRecord
    operating_mode: Literal["default"] = "default"


class NFPredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record: NFCompletedFlowRecord
    operating_mode: Literal["standard", "high_sensitivity"] = "standard"


def model_batch_types(maximum):
    return tuple(
        create_model(
            name,
            __config__=ConfigDict(extra="forbid"),
            records=(list[record], Field(..., min_length=1, max_length=maximum)),
            operating_mode=(mode, default),
        )
        for name, record, mode, default in (
            ("BoTModelBatchRequest", NetworkRecord, Literal["default"], "default"),
            (
                "NFModelBatchRequest",
                NFCompletedFlowRecord,
                Literal["standard", "high_sensitivity"],
                "standard",
            ),
        )
    )


class ModelPredictionResponse(BaseModel):
    model_id: str
    model_version: str
    task: Literal["binary", "multiclass"]
    predicted_class: str
    positive_class_score: float | None
    class_scores: dict[str, float] | None
    score_semantics: str = "Uncalibrated model scores; not proof of an attack or safety"
    operating_mode: str
    applied_threshold: float | None
    input_contract_version: str
    inference_timestamp: datetime
    limitations: list[str]


class ModelBatchResponse(BaseModel):
    predictions: list[ModelPredictionResponse]
    count: int
