"""Stable label-independent assignment of normalized feature-vector groups."""

import hashlib


def validation_group(key: str, seed: int = 20261115) -> bool:
    """Fixed 20% hash partition; independent of row order, labels and chunk size."""
    signature = hashlib.sha256(f"{seed}:{key}".encode()).digest()
    return int.from_bytes(signature[:8], "big") < (1 << 64) // 5
