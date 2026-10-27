"""Settings from environment variables (see backend/README.md)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from chainguard_contract.models import MAX_UPLOAD_BYTES

from . import REPO_ROOT


def _int(name: str, default: int) -> int:
    v = os.environ.get(name)
    return int(v) if v not in (None, "") else default


@dataclass
class Settings:
    data_dir: str = field(default_factory=lambda: os.environ.get("CG_DATA_DIR") or str(REPO_ROOT / "backend" / "data"))
    max_upload_bytes: int = field(default_factory=lambda: _int("CG_MAX_UPLOAD_BYTES", MAX_UPLOAD_BYTES))
    api_key: str | None = field(default_factory=lambda: os.environ.get("CG_API_KEY") or None)
    cors_origins: list[str] = field(default_factory=lambda: [o.strip() for o in os.environ.get(
        "CG_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()])
    workers: int = field(default_factory=lambda: max(1, _int("CG_WORKERS", 2)))
    queue_max: int = field(default_factory=lambda: max(1, _int("CG_QUEUE_MAX", 100)))
    sandbox_timeout_s: int = field(default_factory=lambda: _int("CG_SANDBOX_TIMEOUT_S", 60))
    # LLM (NVIDIA NIM, OpenAI-compatible)
    llm_base_url: str = field(default_factory=lambda: os.environ.get("CG_LLM_BASE_URL", "https://integrate.api.nvidia.com/v1"))
    llm_model: str = field(default_factory=lambda: os.environ.get("CG_LLM_MODEL", "meta/llama-3.1-70b-instruct"))
    llm_api_key: str | None = field(default_factory=lambda: os.environ.get("NIM_API_KEY") or os.environ.get("CG_LLM_API_KEY") or None)
    llm_timeout_s: int = field(default_factory=lambda: _int("CG_LLM_TIMEOUT_S", 60))
    llm_max_findings: int = field(default_factory=lambda: _int("CG_LLM_MAX_FINDINGS", 10))
    evm_max_findings: int = field(default_factory=lambda: _int("CG_EVM_MAX_FINDINGS", 10))
    # set CG_DISABLE_SANDBOX=1 to force the sandbox adapters unavailable (tests / machines without solc)
    disable_sandbox: bool = field(default_factory=lambda: os.environ.get("CG_DISABLE_SANDBOX", "") in ("1", "true", "yes"))
    disable_ml: bool = field(default_factory=lambda: os.environ.get("CG_DISABLE_ML", "") in ("1", "true", "yes"))
