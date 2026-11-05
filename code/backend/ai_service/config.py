from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

CODE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = CODE_DIR.parent / "dataset"


def _load_local_env() -> None:
    env_file = CODE_DIR / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or "=" not in clean:
            continue
        key, value = clean.split("=", 1)
        key, value = key.strip(), value.strip().strip("\"'")
        if key and key.replace("_", "a").isalnum() and key not in os.environ:
            os.environ[key] = value


def _local_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    if parsed.scheme not in {"http", "https"} or not is_loopback or parsed.username or parsed.password:
        raise ValueError(f"{label} must use a loopback host (localhost, 127.0.0.1, or ::1).")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    ollama_url: str
    ollama_model: str
    ollama_embedding_model: str
    embedding_model: str
    embedding_provider: str
    embedding_cache: Path
    dataset_dir: Path
    request_timeout: float
    max_evidence_chars: int
    max_chunks: int

    @classmethod
    def from_env(cls) -> "Settings":
        _load_local_env()
        cache_value = Path(os.getenv("RAG_CACHE_PATH", str(CODE_DIR / "backend" / "ai_rag.sqlite3")))
        if not cache_value.is_absolute():
            cache_value = CODE_DIR / cache_value
        dataset_value = Path(os.getenv("GHOSTGUARD_DATASET_DIR", str(DEFAULT_DATASET)))
        if not dataset_value.is_absolute():
            dataset_value = CODE_DIR.parent / dataset_value
        return cls(
            ollama_url=_local_url(os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"), "OLLAMA_BASE_URL"),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen3:1.7b"),
            ollama_embedding_model=os.getenv("OLLAMA_EMBEDDING_MODEL", "nomic-embed-text"),
            embedding_model=os.getenv("RAG_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
            embedding_provider=os.getenv("RAG_EMBEDDING_PROVIDER", "ollama").casefold(),
            embedding_cache=cache_value.resolve(),
            dataset_dir=dataset_value.resolve(),
            request_timeout=max(2.0, min(float(os.getenv("AI_REQUEST_TIMEOUT", "90")), 300.0)),
            max_evidence_chars=max(500, min(int(os.getenv("AI_MAX_EVIDENCE_CHARS", "12000")), 30000)),
            max_chunks=max(1, min(int(os.getenv("RAG_MAX_RESULTS", "8")), 20)),
        )
