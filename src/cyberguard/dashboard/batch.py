"""Strict, bounded in-memory CSV handling; no feature normalization."""

import csv
import io

import pandas as pd

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_RECORDS = 20_000
FEATURES = ("proto", "sport", "dport")
DEMO_CSV = b"proto,sport,dport\ntcp,49152,80\nudp,50000,53\ntcp,12345,22\nicmp,-1,-1\n"
OUTPUT_COLUMNS = {
    "prediction",
    "model",
    "warning",
    *(f"probability_{c}" for c in ("Normal", "DoS", "DDoS", "Reconnaissance")),
}


class UploadError(ValueError):
    pass


def parse_csv(data, *, model=None):
    features = tuple(model.required_features) if model is not None else FEATURES
    output_columns = (
        OUTPUT_COLUMNS
        | {
            "model_version",
            "operating_mode",
            "applied_threshold",
            "positive_class_score",
            "input_contract_version",
            "inference_timestamp",
        }
        | ({f"score_{c}" for c in model.classes} if model is not None else set())
    )
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError("Upload exceeds 5 MiB. Split it into smaller CSV files.")
    if not data:
        raise UploadError("The upload is empty.")
    try:
        text = data.decode("utf-8-sig")
        if "\x00" in text:
            raise UploadError("CSV files cannot contain NUL characters.")
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader, [])
        if (
            not header
            or any(not h.strip() for h in header)
            or len(set(header)) != len(header)
        ):
            raise UploadError("CSV headers must be unique and nonempty.")
        if not set(features).issubset(header):
            raise UploadError(
                "CSV requires the exact column names " + ", ".join(features) + "."
            )
        if output_columns.intersection(header):
            raise UploadError(
                "Rename columns that conflict with prediction, model, warning or probability output columns."
            )
        rows = []
        for row in reader:
            if len(row) != len(header):
                raise UploadError(
                    f"Malformed CSV record {len(rows) + 1}: column count differs from the header."
                )
            rows.append(row)
            if len(rows) > MAX_RECORDS:
                raise UploadError(
                    "Upload exceeds 20,000 records. Split it into smaller CSV files."
                )
        if not rows:
            raise UploadError("The CSV has no data records.")
        frame = pd.DataFrame(rows, columns=header, dtype=str)
        if model is not None:
            from cyberguard.dashboard.contracts import validate_record

            for index, record in enumerate(
                frame[list(features)].to_dict("records"), start=1
            ):
                try:
                    validate_record(model, record)
                except ValueError as exc:
                    raise UploadError(f"CSV record {index}: {exc}") from None
        return frame
    except (UnicodeError, csv.Error):
        raise UploadError(
            "Malformed CSV: use UTF-8, valid quoting and consistent field counts."
        ) from None


def results_frame(inputs, predictions, *, model=None):
    if len(inputs) != len(predictions):
        raise UploadError(
            "Incomplete predictions; a complete result cannot be exported."
        )
    output = inputs.copy()
    output["prediction"] = [p.prediction for p in predictions]
    output["model"] = [p.model for p in predictions]
    output["warning"] = [p.warning for p in predictions]
    if model is not None:
        for name in (
            "model_version",
            "operating_mode",
            "applied_threshold",
            "input_contract_version",
            "inference_timestamp",
        ):
            output[name] = [getattr(p, name) for p in predictions]
        if any(p.positive_class_score is not None for p in predictions):
            output["positive_class_score"] = [
                p.positive_class_score for p in predictions
            ]
        if any(p.class_scores is not None for p in predictions):
            for label in model.classes:
                output[f"score_{label}"] = [
                    p.class_scores.get(label) if p.class_scores else None
                    for p in predictions
                ]
        return output
    for label in ("Normal", "DoS", "DDoS", "Reconnaissance"):
        if any(p.probabilities is not None for p in predictions):
            output[f"probability_{label}"] = [
                p.probabilities.get(label) if p.probabilities else None
                for p in predictions
            ]
    return output


def safe_csv(frame):
    """Escape untrusted spreadsheet cells and headers on export only."""

    def escape(value):
        if isinstance(value, str) and (
            value.lstrip().startswith(("=", "+", "-", "@"))
            or value.startswith(("\t", "\r", "\n"))
        ):
            return "'" + value
        return value

    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow([escape(c) for c in frame.columns])
    writer.writerows(
        [escape(v) for v in row] for row in frame.itertuples(index=False, name=None)
    )
    return stream.getvalue().encode("utf-8")
