"""Public metadata and input checks. No feature normalization or model execution."""

import math
import re
from decimal import Decimal, InvalidOperation

from pydantic import BaseModel, ConfigDict, model_validator


class Mode(BaseModel):
    id: str
    threshold: float | None


class ModelMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    display_name: str
    description: str
    model_version: str | None
    task: str
    classes: list[str]
    required_features: list[str]
    input_contract_version: str
    input_contract: dict
    input_schema: dict
    available_operating_modes: list[Mode]
    default_operating_mode: str
    limitations: list[str]
    readiness: str
    performance_metadata: dict | None = None

    @model_validator(mode="after")
    def contract(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.id):
            raise ValueError("Invalid model ID")
        for values in (self.classes, self.required_features):
            if (
                not values
                or len(set(values)) != len(values)
                or any(not v for v in values)
            ):
                raise ValueError("Invalid classes/features")
        modes = [m.id for m in self.available_operating_modes]
        if (
            not modes
            or len(set(modes)) != len(modes)
            or self.default_operating_mode not in modes
        ):
            raise ValueError("Invalid operating modes")
        if any(
            m.threshold is not None
            and (not math.isfinite(m.threshold) or not 0 <= m.threshold <= 1)
            for m in self.available_operating_modes
        ):
            raise ValueError("Invalid threshold metadata")
        if (
            self.readiness not in ("ready", "unavailable")
            or not self.display_name
            or not self.input_contract_version
        ):
            raise ValueError("Invalid model metadata")
        if set(self.input_schema.get("required", [])) != set(self.required_features):
            raise ValueError("Input schema mismatch")
        return self

    def threshold(self, mode):
        for option in self.available_operating_modes:
            if option.id == mode:
                return option.threshold
        raise ValueError("Invalid operating mode")


def field_specs(model):
    properties = model.input_schema.get("properties", {})
    try:
        details = {f["name"]: f for f in model.input_contract.get("fields", [])}
    except (TypeError, KeyError):
        raise ValueError("Invalid public field metadata") from None
    if not isinstance(properties, dict):
        raise ValueError("Invalid public input schema")  # noqa: TRY004 -- uniform schema validation error
    expected_count = {
        "bot-iot-header-v1": 3,
        "nf-cse-netflow-v1-completed-flow-v1": 7,
    }.get(model.input_contract_version)
    if expected_count is not None and len(model.required_features) != expected_count:
        raise ValueError("Versioned input contract field count mismatch")
    result = []
    for name in model.required_features:
        prop = properties.get(name, {})
        if not isinstance(prop, dict):
            raise ValueError("Invalid public input field schema")  # noqa: TRY004 -- uniform schema validation error
        variants = prop.get("anyOf", [prop])
        if not isinstance(variants, list) or any(
            not isinstance(v, dict) for v in variants
        ):
            raise ValueError("Invalid public scalar schema")
        types = {v.get("type") for v in variants}
        if not types or not types <= {"string", "integer", "number", "null"}:
            raise ValueError(
                "Unsupported public input schema; no form adapter is available"
            )
        result.append(
            {
                "name": name,
                "label": prop.get("title", name),
                "types": types,
                "help": details.get(name, {}).get("description", ""),
                "minimum": details.get(name, {}).get("minimum", prop.get("minimum")),
                "maximum": details.get(name, {}).get("maximum", prop.get("maximum")),
            }
        )
    return result


def _integer(value, *, hexadecimal=False):
    if type(value) is bool or value is None or isinstance(value, (list, dict)):
        raise ValueError("Expected a finite integral value")
    text = str(value).strip()
    if len(text) > 128 or not text.isascii():
        raise ValueError("Numeric token is too long")
    try:
        if hexadecimal and re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
            return int(text, 16)
        number = Decimal(text)
        if (
            not number.is_finite()
            or number != number.to_integral_value()
            or abs(number) > 2**53 - 1
        ):
            raise ValueError(
                "Expected a finite integral value within the supported range"
            )
        return int(number)
    except (InvalidOperation, OverflowError):
        raise ValueError("Expected a finite integral value") from None


def validate_record(model, record):
    if not isinstance(record, dict) or set(record) != set(model.required_features):
        raise ValueError("Supply exactly the selected model's required features")
    specs = field_specs(model)
    for field in specs:
        value = record[field["name"]]
        kind = {str: "string", int: "integer", float: "number", type(None): "null"}.get(
            type(value)
        )
        if kind not in field["types"] and not (
            kind == "integer" and "number" in field["types"]
        ):
            raise ValueError(f"{field['name']}: unsupported scalar type")
    # The public schema lacks integer-valued-string/sentinel validators. This adapter
    # is deliberately restricted to the frozen NF contract, not guessed from labels.
    if model.input_contract_version == "nf-cse-netflow-v1-completed-flow-v1":
        aliases = model.input_contract.get("protocol_aliases", {})
        for index, field in enumerate(specs):
            name = field["name"]
            value = record[name]
            text = str(value).strip().lower()
            try:
                if index in (1, 2) and text in ("-", "-1"):
                    continue
                number = (
                    aliases[text]
                    if index == 0 and text in aliases
                    else _integer(value, hexadecimal=index in (1, 2))
                )
                if index in (1, 2) and number == -1:
                    continue
                if field["minimum"] is None or field["maximum"] is None:
                    raise ValueError("Backend field ranges are missing")
                if not field["minimum"] <= number <= field["maximum"]:
                    raise ValueError("Value is outside the advertised range")
            except ValueError as exc:
                raise ValueError(f"{name}: {exc}") from None
    return (
        record  # Preserve original tokens; the saved API pipeline owns normalization.
    )


class ModelPrediction(BaseModel):
    model_id: str
    model_version: str
    task: str
    predicted_class: str
    positive_class_score: float | None
    class_scores: dict[str, float] | None
    score_semantics: str
    operating_mode: str
    applied_threshold: float | None
    input_contract_version: str
    inference_timestamp: str
    limitations: list[str]

    @property
    def prediction(self):
        return self.predicted_class

    @property
    def model(self):
        return self.model_id

    @property
    def probabilities(self):
        return self.class_scores

    @property
    def warning(self):
        return " ".join(self.limitations)
