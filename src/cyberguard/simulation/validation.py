"""Canonical-to-API representation without inventing lost protocol information."""

import numpy as np

from cyberguard.core.model_schemas import NFCompletedFlowRecord
from cyberguard.features import nf_cse as nf


def export_vectors(vectors):
    """Fail closed if *any* canonical vector cannot be faithfully replayed.

    Non-transport ports (-3) use raw zero; transport sentinel (-4) uses raw -1.
    Neither conversion changes the normalized model input. Unknown/coalesced
    protocols cannot be reconstructed and are deliberately unsupported.
    """
    values = np.asarray(vectors)
    if values.dtype != np.dtype("int64") or values.ndim != 2 or values.shape[1] != 7:
        raise ValueError("Expected canonical int64 matrix with seven columns")
    if not np.isin(values[:, 0], nf.PROTOCOL_BYTES).all():
        raise ValueError(
            "Cannot reconstruct missing/invalid/coalesced protocol from canonical training data"
        )
    transport = np.isin(values[:, 0], [6, 17])
    ports = values[:, 1:3]
    valid_transport = ((ports >= 0) & (ports <= 65535)) | (ports == nf.SENTINEL)
    if not (
        valid_transport[transport].all()
        and (ports[~transport] == nf.NOT_APPLICABLE).all()
    ):
        raise ValueError("Canonical port statuses cannot be exported faithfully")
    if ((values[:, 3:] < 0) | (values[:, 3:] > nf.MAX_COUNTER)).any():
        raise ValueError(
            "Missing/invalid/out-of-range training counters cannot be exported"
        )
    raw = values.copy()
    raw[~transport, 1:3] = 0
    raw[:, 1:3][raw[:, 1:3] == nf.SENTINEL] = -1
    return raw


def record_from_vector(vector):
    record = dict(zip(nf.RAW_FEATURES, map(int, vector), strict=True))
    NFCompletedFlowRecord.model_validate(record)
    return record


def canonical_vector(record):
    vector = np.array([record[c] for c in nf.RAW_FEATURES], dtype="<i8")
    if vector[0] not in (6, 17):
        vector[1:3] = nf.NOT_APPLICABLE
    else:
        vector[1:3][vector[1:3] == -1] = nf.SENTINEL
    return vector
