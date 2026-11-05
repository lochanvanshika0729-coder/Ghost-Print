from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd
from sqlalchemy import select

from .db import CODE_DIR, Investigation, SessionLocal, UploadedFile

log = logging.getLogger("ghostguard.engine")
ROOT = CODE_DIR.parent
DATASET = ROOT / "dataset"
MAX_FILE_BYTES = 10 * 1024 * 1024
UPLOAD_TYPES = {".csv", ".json", ".txt", ".log", ".pdf", ".png", ".jpg", ".jpeg", ".webp", ".sql"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
                   "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
                   "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
                   "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]


def explain_finding(operation: str, system: str, resource: str, category: str, action: str) -> tuple[str, str]:
    if operation == "REPORT_REMAINING_RECORD":
        reason=f"A subject-linked record is still present in {system}. The {category} policy requires {action.lower() or 'deletion'} before the request can be complete."
        next_action="Remove the record as required by policy, then verify that it is absent."
    elif operation == "REPORT_EXPOSED_PII":
        reason=f"A record in {system} still contains a direct identifier linked to the subject. The {category} policy requires {action.lower() or 'redaction or anonymisation'}."
        next_action="Apply the required transformation and verify that the record can no longer identify the subject."
    elif operation == "REPORT_ACTIVE_DATA_FLOW":
        reason=f"The process resource {resource} is active in {system} and could copy or recreate the subject's data."
        next_action="Disable the flow before cleaning downstream copies, then verify that it is inactive."
    else:
        reason=f"The resource {resource} in {system} has an active restoration path that could bring deleted data back."
        next_action="Block the restore path, then verify that the affected data cannot be restored."
    return reason, next_action


def normalized(value: Any) -> str:
    return str(value if value is not None else "").strip().casefold()


def parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig").to_dict(orient="records")


def values_in(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield from values_in(child)
            elif child is not None:
                yield str(key).casefold(), str(child)
    elif isinstance(value, list):
        for child in value:
            yield from values_in(child)


def field_value(value: Any, names: set[str]):
    return next((v for k, v in values_in(value) if k in names), None)


def _safe_sql_snapshot(script: str) -> list[dict[str, Any]]:
    """Execute only the trusted manifest snapshot in a disposable memory database."""
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
    connection.set_authorizer(lambda action, arg1, arg2, db, trigger:
                              sqlite3.SQLITE_OK if action in safe or (action == sqlite3.SQLITE_PRAGMA and arg1 in {"table_info", "foreign_keys"})
                              or (action == sqlite3.SQLITE_UPDATE and arg1 in {"sqlite_master", "sqlite_temp_master", "sqlite_schema"})
                              or (action == sqlite3.SQLITE_FUNCTION and (arg2 or arg1) in {"json_valid"}) else sqlite3.SQLITE_DENY)
    try:
        connection.executescript(script)
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        records = []
        for table in tables:
            name = table.replace('"', '""')
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{name}")')]
            for values in connection.execute(f'SELECT * FROM "{name}"'):
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


class AuditEngine:
    def __init__(self):
        self.requests = read_csv(DATASET / "deletion_requests.csv")
        self.identities = read_csv(DATASET / "user_identities.csv")
        self.audit_log = read_csv(DATASET / "user_audit_log.csv")
        self.activity = read_csv(DATASET / "system_activity.csv")
        self.rules = {r["data_category"].upper(): r for r in read_csv(DATASET / "deletion_rules.csv")}
        self.manifest = read_csv(DATASET / "evidence_files.csv")
        self.evidence = self._read_evidence()
        self.by_case = {r["case_id"]: r for r in self.requests}
        self.cache: dict[str, dict[str, Any]] = {}

    def _read_evidence(self) -> list[dict[str, Any]]:
        root = (DATASET / "evidence").resolve()
        loaded = []
        for entry in self.manifest:
            relative = entry.get("file_path", "").replace("\\", "/").removeprefix("evidence/")
            path = (root / relative).resolve()
            item = {**entry, "content": "", "records": [], "error": None}
            try:
                path.relative_to(root)
                if path.stat().st_size > MAX_FILE_BYTES:
                    raise ValueError("Evidence file exceeds parser limit")
                ext = path.suffix.casefold()
                if ext == ".json":
                    item["content"] = path.read_text(encoding="utf-8", errors="replace")
                    payload = json.loads(item["content"])
                    item["records"] = payload if isinstance(payload, list) else [payload]
                elif ext == ".sql":
                    item["content"] = path.read_text(encoding="utf-8", errors="replace")
                    item["records"] = _safe_sql_snapshot(item["content"])
                elif ext == ".pdf":
                    from pypdf import PdfReader
                    item["content"] = "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)
                elif ext in {".png", ".jpg", ".jpeg", ".webp"}:
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

        cutoff = parse_time(request.get("audit_at"))
        findings = []
        safe_checks = []
        matched_evidence_ids = []
        resource_missing_evidence_ids = []
        unsupported_policy = {}

        for evidence in self.evidence:
            captured = parse_time(evidence.get("captured_at"))
            if evidence.get("error") or (cutoff and captured and captured > cutoff):
                continue

            records = list(evidence.get("records", []))

            if not records and evidence.get("content"):
                for line in evidence["content"].splitlines():
                    if not any(identifier and identifier in normalized(line) for identifier in identifiers):
                        continue

                    match = re.search(
                        r"\b(?:account|search|support|analytics|export|backup|tombstone|data_flow|audit_record)_[0-9][\w-]*\b",
                        line,
                        re.I
                    )

                    if match:
                        inline = {"resource_id": match.group(), "line": line}
                        email_match = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", line)
                        if email_match:
                            inline["email"] = email_match.group()

                        state_match = re.search(
                            r"\b(NOT_FOUND|ABSENT|DELETED|REDACTED|ANONYMIZED|ANONYMISED|ACTIVE|ENABLED|RUNNING|FOUND|PRESENT|IDENTIFIABLE|BLOCKED|DISABLED)\b",
                            line,
                            re.I
                        )
                        if state_match:
                            inline["state"] = state_match.group(1).upper()

                        records.append(inline)

            for record in records:
                if not isinstance(record, dict) or not self._matches(record, identifiers):
                    continue

                event_time = parse_time(field_value(
                    record,
                    {"event_time", "timestamp", "updated_at", "captured_at", "observed_at", "created_at"}
                ))

                if cutoff and event_time and event_time > cutoff:
                    continue

                if evidence.get("file_id"):
                    matched_evidence_ids.append(evidence["file_id"])

                resource_value = record.get(
                    "resource_id",
                    record.get("file_id", record.get("activity_id", ""))
                )
                resource = str(resource_value).strip() if resource_value is not None else ""

                if not resource:
                    if evidence.get("file_id"):
                        resource_missing_evidence_ids.append(evidence["file_id"])
                    continue

                category = self._category(record, resource)
                rule = self.rules.get(category, {})
                treatment = str(rule.get("required_action", "")).upper()

                if treatment not in {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}:
                    unsupported_policy.setdefault(category, set()).add(evidence.get("file_id", ""))

                system = str(record.get(
                    "system_id",
                    record.get("origin_system", record.get("source_system", ""))
                ))

                system = system or {
                    "USER_PROFILE": "account_service",
                    "SEARCH_INDEX_ENTRY": "search_service",
                    "ANALYTICS_PROFILE": "analytics_platform",
                    "PRODUCT_TELEMETRY": "analytics_platform",
                    "SUPPORT_MESSAGE": "support_platform",
                    "SUPPORT_ATTACHMENT": "support_platform",
                    "USER_EXPORT": "export_service",
                    "BACKUP_ARCHIVE": "backup_service",
                    "ACCOUNT_TOMBSTONE": "identity_service",
                    "SECURITY_AUDIT_LOG": "security_service"
                }.get(category, "unknown")

                state = self._state(record)
                active = state in {"ACTIVE", "ENABLED", "RUNNING", "RESTORABLE", "AVAILABLE"}

                pii = any(
                    k in {"email", "phone", "full_name", "name", "email_hash"} and v not in (None, "")
                    for k, v in values_in(record)
                )

                operation = None
                step_state = "PRESENT"

                if "data_flow" in resource.casefold() and active:
                    operation, step_state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
                elif category == "BACKUP_ARCHIVE" and active:
                    operation, step_state = "REPORT_RESTORE_RISK", "ACTIVE"
                elif treatment == "RETAIN":
                    safe_checks.append((
                        system, resource, "VERIFY_RECORD_PRESENT", "PRESENT",
                        evidence["file_id"], category
                    ))
                    continue
                elif treatment == "DELETE" and state not in {"ABSENT", "NOT_FOUND", "DELETED"}:
                    operation = "REPORT_REMAINING_RECORD"
                elif treatment in {"REDACT", "ANONYMIZE"} and pii:
                    operation = "REPORT_EXPOSED_PII"

                if operation:
                    excerpt = " ".join(
                        str(v) for k, v in record.items()
                        if k.casefold() in {"state", "status", "category", "event_type", "operation_result"}
                    )[:240]

                    reason, recommended = explain_finding(
                        operation, system, resource, category, treatment
                    )

                    findings.append({
                        "phase": "FINDING",
                        "system_id": system,
                        "resource_id": resource,
                        "operation": operation,
                        "state": step_state,
                        "evidence_id": evidence["file_id"],
                        "data_category": category,
                        "evidence_excerpt": excerpt,
                        "policy_action": treatment,
                        "reason": reason,
                        "recommended_action": recommended,
                        "_record": record
                    })

                elif treatment in {"DELETE", "REDACT", "ANONYMIZE"}:
                    op = {
                        "DELETE": "VERIFY_RECORD_ABSENT",
                        "REDACT": "VERIFY_RECORD_REDACTED",
                        "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED"
                    }[treatment]

                    state_out = {
                        "DELETE": "ABSENT",
                        "REDACT": "REDACTED",
                        "ANONYMIZE": "ANONYMIZED"
                    }[treatment]

                    safe_checks.append((
                        system, resource, op, state_out, evidence["file_id"], category
                    ))

        findings = self._dedupe(findings)