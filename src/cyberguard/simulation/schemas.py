"""Explicit, immutable generator configuration."""

import math
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, localcontext


@dataclass(frozen=True)
class GeneratorConfig:
    count: int = 10000
    seed: int = 42
    benign_ratio: float = 0.9
    mode: str = "empirical"
    protocols: tuple[int, ...] = ()
    destination_ports: tuple[int, ...] = ()
    perturbation: float = 0.1

    def __post_init__(self):
        for name in ("count", "seed"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if not 1 <= self.count <= 2**63 - 1:
            raise ValueError("count must be in 1..2**63-1")
        if not math.isfinite(self.benign_ratio) or not 0 <= self.benign_ratio <= 1:
            raise ValueError("benign_ratio must be finite in [0,1]")
        if self.mode not in {"empirical", "synthetic"}:
            raise ValueError("mode must be empirical or synthetic")
        if not math.isfinite(self.perturbation) or not 0 < self.perturbation <= 0.25:
            raise ValueError("perturbation must be finite in (0,0.25]")
        for name, maximum in (("protocols", 255), ("destination_ports", 65535)):
            if any(
                type(v) is not int or not 0 <= v <= maximum for v in getattr(self, name)
            ):
                raise ValueError(f"{name} must contain integer values in 0..{maximum}")

    @property
    def benign_count(self):
        # Enough precision for an int64 count times a finite float's decimal
        # representation, including values very close to a half-up boundary.
        with localcontext() as context:
            context.prec = 80
            return int(
                (Decimal(str(self.benign_ratio)) * self.count).quantize(
                    Decimal(1), rounding=ROUND_HALF_UP
                )
            )
