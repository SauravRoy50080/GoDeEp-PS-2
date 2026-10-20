"""Environment-based configuration; local data never belongs in Git."""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GODEEP_", env_file=BACKEND_ROOT / ".env", extra="ignore"
    )
    app_name: str = "GoDeEp API"
    environment: Literal["development", "test", "production"] = "development"
    database_url: SecretStr = SecretStr("postgresql+psycopg://godeep@127.0.0.1:5432/godeep")
    evidence_root: Path = BACKEND_ROOT / "data" / "evidence"
    max_upload_bytes: int = Field(default=200 * 1024 * 1024, ge=1)
    max_archive_entries: int = Field(default=10000, ge=1, le=65534)
    max_uncompressed_bytes: int = Field(default=1024 * 1024 * 1024, ge=1)
    max_central_directory_bytes: int = Field(default=8 * 1024 * 1024, ge=1)

    session_ttl_seconds: int = Field(default=28800, ge=60, le=86400)
    login_max_attempts: int = Field(default=5, ge=1, le=20)
    login_lock_seconds: int = Field(default=900, ge=60, le=86400)

    job_timeout_seconds: int = Field(default=60, ge=1, le=300)
    worker_poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    max_result_bytes: int = Field(default=1048576, ge=1024, le=10485760)

    max_manifest_bytes: int = Field(default=2097152, ge=1024, le=8388608)
    max_manifest_nodes: int = Field(default=20000, ge=10, le=100000)
    max_signature_bytes: int = Field(default=8388608, ge=1024, le=16777216)
    max_certificate_member_bytes: int = Field(default=1048576, ge=1024, le=4194304)
    max_certificates: int = Field(default=64, ge=1, le=256)

    max_dex_bytes: int = Field(default=16777216, ge=112, le=67108864)
    max_dex_total_bytes: int = Field(default=67108864, ge=112, le=268435456)
    max_dex_files: int = Field(default=32, ge=1, le=128)
    max_dex_identifiers: int = Field(default=100000, ge=1, le=1000000)
    max_dex_string_bytes: int = Field(default=8192, ge=16, le=65536)
    max_dex_findings: int = Field(default=500, ge=1, le=2000)

    max_dex_encoded_methods: int = Field(default=10000, ge=1, le=100000)
    max_dex_code_units: int = Field(default=1000000, ge=1, le=10000000)

    max_review_findings: int = Field(default=500, ge=1, le=2000)
    max_review_evidence: int = Field(default=50, ge=1, le=200)

    signer_java_path: Path | None = None
    signer_jar_path: Path | None = None
    signer_jar_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    signer_timeout_seconds: int = Field(default=20, ge=1, le=120)
    max_signer_output_bytes: int = Field(default=65536, ge=1024, le=262144)

    max_resource_files: int = Field(default=128, ge=1, le=1000)
    max_resource_bytes: int = Field(default=1048576, ge=64, le=8388608)
    max_resource_total_bytes: int = Field(default=16777216, ge=64, le=67108864)
    max_resource_nodes: int = Field(default=2000, ge=1, le=20000)
    max_resource_findings: int = Field(default=500, ge=1, le=2000)

    intel_feed_path: Path | None = None
    intel_feed_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    intel_max_feed_age_days: int = Field(default=30, ge=1, le=365)
    max_intel_feed_bytes: int = Field(default=2097152, ge=1024, le=8388608)
    max_intel_candidates: int = Field(default=1000, ge=1, le=5000)
    max_intel_matches: int = Field(default=50, ge=1, le=200)

    max_report_bytes: int = Field(default=10485760, ge=1024, le=52428800)

    max_comparison_items: int = Field(default=200, ge=1, le=1000)
    max_comparison_bytes: int = Field(default=2097152, ge=1024, le=10485760)
