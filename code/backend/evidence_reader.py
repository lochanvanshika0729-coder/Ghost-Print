"""Safe, evidence-reference-preserving readers for supported artifact formats."""
from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd

log = logging.getLogger("ghostguard.evidence_reader")
MAX_EVIDENCE_BYTES = 10 * 1024 * 1024


def read_sql_snapshot(script: str) -> list[dict[str, Any]]:
    """Read a supplied SQLite snapshot in memory while denying unsafe SQL actions."""
    connection = sqlite3.connect(":memory:")

    def valid_json(value: Any) -> int:
        try:
            json.loads(value)
            return 1
        except (TypeError, ValueError):
            return 0

    connection.create_function("json_valid", 1, valid_json, deterministic=True)
    allowed = {
        sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT,
    }

    def authorize(action: int, arg1: str | None, arg2: str | None, _db: str | None, _trigger: str | None) -> int:
        if action in allowed:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and arg1 == "table_info":
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_UPDATE and arg1 in {"sqlite_master", "sqlite_temp_master", "sqlite_schema"}:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and (arg2 or arg1) == "json_valid":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    connection.set_authorizer(authorize)
    try:
        connection.executescript(script)
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        records: list[dict[str, Any]] = []
        for table in tables:
            quoted = table.replace('"', '""')
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{quoted}")')]
            for values in connection.execute(f'SELECT * FROM "{quoted}"'):
                record = dict(zip(columns, values))
                for key, value in list(record.items()):
                    if isinstance(value, str) and value[:1] in "[{":
                        try:
                            record[key] = json.loads(value)
                        except json.JSONDecodeError:
                            pass
                record.setdefault("collection_name", table)
                records.append(record)
        return records
    finally:
        connection.close()


class EvidenceReader:
    """Load evidence paths listed in the manifest and retain file_id citations."""

    def __init__(self, evidence_root: Path, manifest: list[dict[str, Any]], max_bytes: int = MAX_EVIDENCE_BYTES):
        self.root = Path(evidence_root).resolve()
        self.manifest = manifest
        self.max_bytes = max_bytes

    def read_all(self) -> list[dict[str, Any]]:
        loaded: list[dict[str, Any]] = []
        for entry in self.manifest:
            relative = str(entry.get("file_path", "")).replace("\\", "/")
            if relative.startswith("evidence/"):
                relative = relative[len("evidence/"):]
            path = (self.root / relative).resolve()
            item = {**entry, "content": "", "records": [], "error": None}
            try:
                path.relative_to(self.root)
                if not path.is_file():
                    raise FileNotFoundError("Evidence file is missing")
                if path.stat().st_size > self.max_bytes:
                    raise ValueError("Evidence file exceeds parser limit")
                extension = path.suffix.casefold()
                if extension == ".json":
                    item["content"] = path.read_text(encoding="utf-8", errors="replace")
                    payload = json.loads(item["content"])
                    item["records"] = payload if isinstance(payload, list) else [payload]
                elif extension == ".sql":
                    item["content"] = path.read_text(encoding="utf-8", errors="replace")
                    item["records"] = read_sql_snapshot(item["content"])
                elif extension == ".csv":
                    frame = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
                    item["records"] = frame.to_dict(orient="records")
                elif extension == ".pdf":
                    from pypdf import PdfReader
                    item["content"] = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
                elif extension in {".png", ".jpg", ".jpeg", ".webp"}:
                    from PIL import Image
                    import pytesseract
                    item["content"] = pytesseract.image_to_string(Image.open(path))
                else:
                    item["content"] = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                item["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
                log.warning("Could not read evidence %s: %s", entry.get("file_id"), type(exc).__name__)
            loaded.append(item)
        return loaded
