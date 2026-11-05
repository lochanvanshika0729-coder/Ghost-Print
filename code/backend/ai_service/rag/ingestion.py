from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Document:
    document_id: str
    text: str
    metadata: dict[str, Any]


def normalize(value: Any) -> str:
    return str(value if value is not None else "").strip().casefold()


def chunk_text(text: str, *, size: int = 1100, overlap: int = 140) -> list[str]:
    clean = re.sub(r"[ \t]+", " ", str(text or "")).strip()
    if not clean:
        return []
    if size <= overlap:
        raise ValueError("Chunk size must be larger than overlap")
    chunks = []
    start = 0
    while start < len(clean):
        end = min(len(clean), start + size)
        if end < len(clean):
            boundary = max(clean.rfind("\n", start, end), clean.rfind(". ", start, end), clean.rfind(" ", start, end))
            if boundary > start + size // 2:
                end = boundary + (1 if clean[boundary:boundary + 1] == "\n" else 2 if clean[boundary:boundary + 2] == ". " else 0)
        chunk = clean[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(clean):
            break
        start = max(start + 1, end - overlap)
    return chunks


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _read_sql(path: Path) -> list[dict[str, Any]]:
    """Read a dataset snapshot using an isolated, read-only SQLite authorizer."""
    connection = sqlite3.connect(":memory:")
    def valid_json(value):
        try:
            json.loads(value)
            return 1
        except (TypeError, ValueError):
            return 0
    connection.create_function("json_valid", 1, valid_json, deterministic=True)
    safe = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_CREATE_TEMP_INDEX, sqlite3.SQLITE_REINDEX, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_TRANSACTION,
            sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT}
    connection.set_authorizer(lambda action, arg1, arg2, _db, _trigger:
        sqlite3.SQLITE_OK if action in safe or (action == sqlite3.SQLITE_PRAGMA and arg1 in {"table_info", "foreign_keys"})
        or (action == sqlite3.SQLITE_UPDATE and arg1 in {"sqlite_master", "sqlite_temp_master", "sqlite_schema"})
        or (action == sqlite3.SQLITE_FUNCTION and (arg2 or arg1) == "json_valid")
        else sqlite3.SQLITE_DENY)
    try:
        connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        output = []
        for table in tables:
            escaped = table.replace('"', '""')
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{escaped}")')]
            for values in connection.execute(f'SELECT * FROM "{escaped}"'):
                record = dict(zip(columns, values))
                record["collection_name"] = table
                output.append(record)
        return output
    finally:
        connection.close()


def _flatten_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value or "")


def _system_for_resource(resource_id: str) -> str:
    prefixes = {
        "account": "account_service", "search": "search_service", "support": "support_platform",
        "analytics": "analytics_platform", "telemetry": "analytics_platform", "export": "export_service",
        "backup": "backup_service", "archive": "archive_service", "audit_record": "security_service",
        "data_flow": "integration_service", "cache": "cache_service", "replica": "database_service",
    }
    value = str(resource_id or "").casefold()
    return next((system for prefix, system in prefixes.items() if value.startswith(prefix + "_")), "")


class DatasetIngestor:
    CSV_SOURCES = {
        "deletion_requests.csv": "request",
        "user_identities.csv": "identity",
        "user_audit_log.csv": "identity_history",
        "system_activity.csv": "system_activity",
        "deletion_rules.csv": "deletion_policy",
    }

    def __init__(self, dataset_dir: Path):
        self.dataset_dir = Path(dataset_dir).resolve()
        self.evidence_root = (self.dataset_dir / "evidence").resolve()
        self.manifest = _rows(self.dataset_dir / "evidence_files.csv")
        self.requests = _rows(self.dataset_dir / "deletion_requests.csv")
        self.identities = _rows(self.dataset_dir / "user_identities.csv")
        self.audit_log = _rows(self.dataset_dir / "user_audit_log.csv")
        self.activity = _rows(self.dataset_dir / "system_activity.csv")
        self.rules = _rows(self.dataset_dir / "deletion_rules.csv")
        self.requests_by_id = {row.get("case_id", ""): row for row in self.requests}
        self.manifest_by_id = {row.get("file_id", ""): row for row in self.manifest}
        self._records_by_file: dict[str, list[dict[str, Any]]] = {}
        self.documents = self._build_documents()
        self.content_hashes = {doc.metadata.get("content_hash") for doc in self.documents}

    def _build_documents(self) -> list[Document]:
        docs: list[Document] = []
        for name, kind in self.CSV_SOURCES.items():
            for index, row in enumerate(_rows(self.dataset_dir / name)):
                text = _flatten_text(row)
                key = row.get("case_id") or row.get("user_id") or row.get("audit_id") or row.get("activity_id") or str(index)
                docs.append(Document(f"dataset:{name}:{key}", text, {
                    "kind": kind, "source_file": name, "record_id": key,
                    "case_id": row.get("case_id", ""), "user_id": row.get("user_id", ""),
                    "data_category": row.get("data_category", row.get("category", "")),
                }))
        seen: dict[str, int] = {}
        for entry in self.manifest:
            file_id = entry.get("file_id", "")
            file_path = entry.get("file_path", "").replace("\\", "/")
            relative = file_path.removeprefix("evidence/")
            path = (self.evidence_root / relative).resolve()
            try:
                path.relative_to(self.evidence_root)
                if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
                    continue
                ext = path.suffix.casefold()
                records: list[dict[str, Any]] = []
                if ext == ".json":
                    content = path.read_text(encoding="utf-8", errors="replace")
                    payload = json.loads(content)
                    records = payload if isinstance(payload, list) else [payload]
                elif ext == ".sql":
                    content = path.read_text(encoding="utf-8", errors="replace")
                    records = _read_sql(path)
                elif ext == ".pdf":
                    from pypdf import PdfReader
                    content = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
                elif ext in {".png", ".jpg", ".jpeg", ".webp"}:
                    from PIL import Image
                    import pytesseract
                    content = pytesseract.image_to_string(Image.open(path))
                else:
                    content = path.read_text(encoding="utf-8", errors="replace")
                if records:
                    for index, record in enumerate(records):
                        if not isinstance(record, dict):
                            record = {"value": record}
                        text = _flatten_text(record)
                        records[index] = record
                        self._record_doc_chunks(docs, seen, file_id, entry, text, record, index)
                else:
                    self._record_doc_chunks(docs, seen, file_id, entry, content, {}, 0)
                self._records_by_file[file_id] = records
            except Exception:
                # Keep failures out of logs and API errors; the manifest still reports readability.
                continue
        return docs

    @staticmethod
    def _record_doc_chunks(docs, seen, file_id, entry, text, record, record_index):
        resource_id = str(record.get("resource_id") or record.get("activity_id") or "")
        if not resource_id:
            match = re.search(r"\b(?:account|search|support|analytics|telemetry|export|backup|audit_record|data_flow|archive|cache|replica|attachment|message|job|marketing|tombstone)_[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*\b", text, re.IGNORECASE)
            resource_id = match.group(0) if match else ""
        source_system = str(record.get("system_id") or record.get("origin_system") or record.get("source_system") or "")
        if not source_system:
            source_system = _system_for_resource(resource_id)
        for chunk_index, chunk in enumerate(chunk_text(text)):
            content_hash = hashlib.sha256(chunk.casefold().encode("utf-8")).hexdigest()
            if content_hash in seen:
                index = seen[content_hash]
                existing = docs[index]
                sources = set(existing.metadata.get("evidence_ids", []))
                sources.add(file_id)
                evidence_sources = list(existing.metadata.get("evidence_sources", []))
                source = {"evidence_id": file_id, "file_path": entry.get("file_path", ""),
                          "captured_at": entry.get("captured_at", ""), "origin": entry.get("origin", ""),
                          "source_system": source_system}
                if source not in evidence_sources:
                    evidence_sources.append(source)
                metadata = {**existing.metadata, "evidence_ids": sorted(sources),
                            "evidence_sources": evidence_sources,
                            "duplicate_sources": sorted(set(existing.metadata.get("duplicate_sources", [])) | {entry.get("file_path", "")})}
                docs[index] = Document(existing.document_id, existing.text, metadata)
                continue
            seen[content_hash] = len(docs)
            docs.append(Document(f"evidence:{file_id}:{record_index}:{chunk_index}", chunk, {
                "kind": "evidence", "evidence_id": file_id,
                "evidence_ids": [file_id],
                "evidence_sources": [{"evidence_id": file_id, "file_path": entry.get("file_path", ""),
                                      "captured_at": entry.get("captured_at", ""), "origin": entry.get("origin", ""),
                                      "source_system": source_system}],
                "source_file": entry.get("file_path", ""), "source_system": str(
                    source_system),
                "resource_id": resource_id,
                "data_category": str(record.get("data_category") or record.get("category") or ""),
                "captured_at": entry.get("captured_at", ""), "origin": entry.get("origin", ""),
                "content_hash": content_hash, "record_index": record_index,
            }))

    @staticmethod
    def aliases(identity: dict[str, str], history: list[dict[str, str]], cutoff: str) -> set[str]:
        cutoff_time = _time(cutoff)
        aliases = {normalize(identity.get("user_id"))} if identity.get("user_id") else set()
        updated = _time(identity.get("updated_at"))
        if not cutoff_time or not updated or updated <= cutoff_time:
            aliases.update(normalize(identity.get(key)) for key in ("email", "email_hash", "phone", "name") if identity.get(key))
        for event in history:
            when = _time(event.get("event_time"))
            if cutoff_time and (not when or when > cutoff_time):
                continue
            if normalize(event.get("field_name")) not in {"email", "email_hash", "phone", "name"}:
                continue
            aliases.update(normalize(event.get(key)) for key in ("old_value", "new_value") if event.get(key))
        return {value for value in aliases if value}

    def resolve_case(self, case_id: str) -> tuple[dict[str, str], dict[str, str], set[str], list[dict[str, str]]]:
        request = self.requests_by_id.get(case_id)
        if not request:
            raise KeyError("Case not found")
        email = normalize(request.get("email"))
        cutoff = request.get("audit_at", "")
        matched = []
        for identity in self.identities:
            history = [row for row in self.audit_log if row.get("user_id") == identity.get("user_id")]
            aliases = self.aliases(identity, history, cutoff)
            if email in aliases:
                matched.append((identity, aliases, history))
        if len(matched) != 1:
            return request, {}, set(), []
        identity, aliases, history = matched[0]
        return request, identity, aliases, history

    def record_matches_aliases(self, record: dict[str, Any], aliases: set[str]) -> bool:
        for key, value in record.items():
            if isinstance(value, (dict, list)):
                if self.record_matches_aliases(value if isinstance(value, dict) else {"items": value}, aliases):
                    return True
            elif normalize(value) in aliases:
                return True
        return False

    def evidence_records(self, evidence_id: str) -> list[dict[str, Any]]:
        return list(self._records_by_file.get(evidence_id, []))


def _time(value: str | None) -> float | None:
    if not value:
        return None
    from datetime import datetime, timezone
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return None
