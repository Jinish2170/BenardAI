"""Environment-driven configuration."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import dotenv_values, load_dotenv

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Bernard pulls the LLM key from the user's central cc-nim .env if it isn't
# set locally. This avoids maintaining two copies of the NVIDIA NIM key.
CCNIM_ENV_PATHS = [
    os.getenv("CCNIM_ENV"),                                     # explicit override
    r"C:\files\coding dev era\claude code\cc-nim\.env",         # known user path
    str(Path.home() / "cc-nim" / ".env"),
]


def _ccnim_nvidia_key() -> str:
    """Return NVIDIA_NIM_API_KEY from the first cc-nim/.env that defines it."""
    for path in CCNIM_ENV_PATHS:
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            continue
        try:
            values = dotenv_values(p)
            key = values.get("NVIDIA_NIM_API_KEY") or values.get("NVIDIA_API_KEY")
            if key:
                return key
        except Exception:
            continue
    return ""


def _resolve_llm_key() -> str:
    """Local LLM_API_KEY wins; otherwise fall back to cc-nim's NVIDIA key."""
    local = os.getenv("LLM_API_KEY", "")
    if local:
        return local
    return _ccnim_nvidia_key()


@dataclass(frozen=True)
class LLMConfig:
    base_url: str = os.getenv("LLM_BASE_URL", "https://integrate.api.nvidia.com/v1")
    api_key: str = _resolve_llm_key()
    model: str = os.getenv("LLM_MODEL", "meta/llama-3.3-70b-instruct")
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "2000"))


@dataclass(frozen=True)
class IntelConfig:
    vt_api_key: str = os.getenv("VT_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    abusech_api_key: str = os.getenv("ABUSECH_API_KEY", "")
    request_timeout_s: float = float(os.getenv("INTEL_TIMEOUT_S", "12"))


@dataclass(frozen=True)
class StorageConfig:
    analyses_dir: Path = Path(os.getenv("BERNARD_ANALYSES_DIR", str(REPO_ROOT / "analyses")))
    rules_dir: Path = Path(os.getenv("BERNARD_RULES_DIR", str(REPO_ROOT / "rules")))
    mitre_dir: Path = Path(os.getenv("BERNARD_MITRE_DIR", str(REPO_ROOT / "data" / "mitre-attack-stix")))


@dataclass(frozen=True)
class ServerConfig:
    port: int = int(os.getenv("PORT", "3003"))
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "100"))
    analysis_timeout_s: int = int(os.getenv("ANALYSIS_TIMEOUT_S", "120"))


@dataclass(frozen=True)
class Config:
    llm: LLMConfig = LLMConfig()
    intel: IntelConfig = IntelConfig()
    storage: StorageConfig = StorageConfig()
    server: ServerConfig = ServerConfig()


CONFIG = Config()


def require_llm() -> None:
    if not CONFIG.llm.api_key:
        raise RuntimeError(
            "LLM_API_KEY is not set. Copy .env.example to .env and add an NVIDIA NIM key "
            "(free at https://build.nvidia.com/) or any OpenAI-compatible provider."
        )
