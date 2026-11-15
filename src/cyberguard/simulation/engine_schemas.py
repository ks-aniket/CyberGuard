"""Bounded public Simulation Lab configuration; no client-supplied paths."""

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SimulationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    model_id: str = "nf_cse_binary_completed_flow"
    mode: Literal["empirical", "synthetic"] = "empirical"
    benign_ratio: float | None = Field(default=None, ge=0, le=1)
    attack_ratio: float | None = Field(default=None, ge=0, le=1)
    seed: int = Field(default=42, ge=0, le=2**63 - 1, strict=True)
    generation_rate: float = Field(default=100, ge=1, le=500)
    max_duration: float = Field(default=60, gt=0, le=3600)
    max_records: int = Field(default=6000, ge=1, le=1000000, strict=True)
    batch_size: int = Field(default=32, ge=1, le=128, strict=True)
    queue_capacity: int = Field(default=256, ge=1, le=4096, strict=True)
    event_capacity: int = Field(default=500, ge=1, le=2000, strict=True)
    history_capacity: int = Field(default=120, ge=1, le=600, strict=True)
    operating_mode: Literal["standard", "high_sensitivity"] = "standard"

    @model_validator(mode="after")
    def ratios(self):
        if self.benign_ratio is None and self.attack_ratio is None:
            self.benign_ratio, self.attack_ratio = 0.9, 0.1
        elif self.benign_ratio is None:
            self.benign_ratio = float(Decimal(1) - Decimal(str(self.attack_ratio)))
        elif self.attack_ratio is None:
            self.attack_ratio = float(Decimal(1) - Decimal(str(self.benign_ratio)))
        elif abs(self.benign_ratio + self.attack_ratio - 1) > 1e-12:
            raise ValueError("benign_ratio and attack_ratio must sum to one")
        return self
