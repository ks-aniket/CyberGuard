"""Small environment-based server configuration; no implicit .env loading."""

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODEL = PROJECT_ROOT / "models/network/bot_iot_restricted_baseline.joblib"


@dataclass(frozen=True)
class Settings:
    network_model_path: Path = DEFAULT_MODEL
    nf_cse_model_path: Path = (
        PROJECT_ROOT / "models/network/nf_cse_binary_completed_flow.joblib"
    )
    nf_cse_evaluation_dir: Path = (
        PROJECT_ROOT / "reports/model_evaluation/nf_cse_binary/final_test"
    )
    max_model_request_bytes: int = 1048576
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    max_batch_size: int = 1000
    log_level: str = "INFO"

    def __post_init__(self):
        path = Path(self.network_model_path).expanduser()
        object.__setattr__(self, "network_model_path", (PROJECT_ROOT / path).resolve())
        for name in ("nf_cse_model_path", "nf_cse_evaluation_dir"):
            object.__setattr__(
                self,
                name,
                (PROJECT_ROOT / Path(getattr(self, name)).expanduser()).resolve(),
            )
        if self.max_model_request_bytes < 1:
            raise ValueError("CYBERGUARD_MAX_MODEL_REQUEST_BYTES must be positive")
        object.__setattr__(self, "log_level", self.log_level.upper())
        if not self.api_host.strip():
            raise ValueError("CYBERGUARD_API_HOST must not be blank")
        if not 1 <= self.api_port <= 65535:
            raise ValueError("CYBERGUARD_API_PORT must be between 1 and 65535")
        if self.max_batch_size < 1:
            raise ValueError("CYBERGUARD_MAX_BATCH_SIZE must be positive")
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(
                "CYBERGUARD_LOG_LEVEL must be DEBUG/INFO/WARNING/ERROR/CRITICAL"
            )

    @classmethod
    def from_env(cls):
        def integer(name, default):
            try:
                return int(os.environ.get(name, default))
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc

        return cls(
            network_model_path=Path(
                os.environ.get("CYBERGUARD_NETWORK_MODEL_PATH", str(DEFAULT_MODEL))
            ),
            nf_cse_model_path=Path(
                os.environ.get(
                    "CYBERGUARD_NF_CSE_MODEL_PATH",
                    str(
                        PROJECT_ROOT
                        / "models/network/nf_cse_binary_completed_flow.joblib"
                    ),
                )
            ),
            nf_cse_evaluation_dir=Path(
                os.environ.get(
                    "CYBERGUARD_NF_CSE_EVALUATION_DIR",
                    str(
                        PROJECT_ROOT
                        / "reports/model_evaluation/nf_cse_binary/final_test"
                    ),
                )
            ),
            max_model_request_bytes=integer(
                "CYBERGUARD_MAX_MODEL_REQUEST_BYTES", 1048576
            ),
            api_host=os.environ.get("CYBERGUARD_API_HOST", "127.0.0.1"),
            api_port=integer("CYBERGUARD_API_PORT", 8000),
            max_batch_size=integer("CYBERGUARD_MAX_BATCH_SIZE", 1000),
            log_level=os.environ.get("CYBERGUARD_LOG_LEVEL", "INFO"),
        )
