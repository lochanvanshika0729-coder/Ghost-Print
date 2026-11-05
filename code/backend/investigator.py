"""Evidence-backed record discovery and recreation-risk classification."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def normalized(value: Any) -> str:
    return str(value if value is not None else "").strip().casefold()


def parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


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
    return next((child for key, child in values_in(value) if key in names), None)


def explain_finding(operation: str, system: str, resource: str, category: str, action: str) -> tuple[str, str]:
    if operation == "REPORT_REMAINING_RECORD":
        reason = f"A subject-linked record is still present in {system}. The {category} policy requires {action.lower() or 'deletion'} before the request can be complete."
        next_action = "Remove the record as required by policy, then verify that it is absent."
    elif operation == "REPORT_EXPOSED_PII":
        reason = f"A record in {system} still contains a direct identifier linked to the subject. The {category} policy requires {action.lower() or 'redaction or anonymisation'}."
        next_action = "Apply the required transformation and verify that the record can no longer identify the subject."
    elif operation == "REPORT_ACTIVE_DATA_FLOW":
        reason = f"The process resource {resource} is active in {system} and could copy or recreate the subject's data."
        next_action = "Disable the flow before cleaning downstream copies, then verify that it is inactive."
    else:
        reason = f"The resource {resource} in {system} has an active restoration path that could bring deleted data back."
        next_action = "Block the restore path, then verify that the affected data cannot be restored."
    return reason, next_action


class EvidenceInvestigator:
    """Search supplied artifacts using a resolved identity and audit cutoff."""

    def __init__(self, rules: dict[str, dict[str, str]]):
        self.rules = rules

    @staticmethod
    def _category(record: dict[str, Any], resource: str) -> str:
        category = str(field_value(record, {"data_category", "category"}) or "").upper()
        if category in self.rules:
            return category
        context = (str(record.get("collection_name", "")) + " " + resource).casefold()
        patterns = [
            ("tombstone", "ACCOUNT_TOMBSTONE"), ("security_audit", "SECURITY_AUDIT_LOG"),
            ("legal_hold", "LEGAL_HOLD_RECORD"), ("backup", "BACKUP_ARCHIVE"), ("archive", "BACKUP_ARCHIVE"),
            ("secondary_identifier", "SECONDARY_IDENTIFIER"), ("cache", "CACHE_ENTRY"),
            ("analytics", "ANALYTICS_PROFILE"), ("telemetry", "PRODUCT_TELEMETRY"),
            ("attachment", "SUPPORT_ATTACHMENT"), ("support", "SUPPORT_MESSAGE"),
            ("search", "SEARCH_INDEX_ENTRY"), ("index", "SEARCH_INDEX_ENTRY"),
            ("export", "USER_EXPORT"), ("marketing", "MARKETING_PROFILE"),
            ("email_delivery", "EMAIL_DELIVERY_LOG"), ("account", "USER_PROFILE"),
        ]
        return next((result for token, result in patterns if token in context), "UNKNOWN")

    @staticmethod
    def _state(record: dict[str, Any]) -> str:
        value = field_value(record, {"record_state", "state", "status", "account_status", "operation_result", "restore_status"})
        return str(value).upper() if value not in (None, "") else "UNKNOWN"

    @staticmethod
    def _inline_records(content: str, identifiers: set[str]) -> list[dict[str, Any]]:
        records = []
        for line in content.splitlines():
            if not any(identifier and identifier in normalized(line) for identifier in identifiers):
                continue
            match = re.search(r"\b(?:account|search|support|analytics|export|backup|tombstone|data_flow|audit_record)_[0-9][\w-]*\b", line, re.I)
            if not match:
                continue
            inline = {"resource_id": match.group(), "line": line}
            email = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", line)
            if email:
                inline["email"] = email.group()
            state = re.search(r"\b(NOT_FOUND|ABSENT|DELETED|REDACTED|ANONYMIZED|ANONYMISED|ACTIVE|ENABLED|RUNNING|FOUND|PRESENT|IDENTIFIABLE|BLOCKED|DISABLED)\b", line, re.I)
            if state:
                inline["state"] = state.group(1).upper()
            records.append(inline)
        return records

    def investigate(
        self, evidence_items: list[dict[str, Any]], identifiers: set[str], audit_cutoff: datetime | None
    ) -> tuple[list[dict[str, Any]], list[tuple[str, str, str, str, str, str]]]:
        findings: list[dict[str, Any]] = []
        safe_checks: list[tuple[str, str, str, str, str, str]] = []
        for evidence in evidence_items:
            captured = parse_time(evidence.get("captured_at"))
            if evidence.get("error") or (audit_cutoff and captured and captured > audit_cutoff):
                continue
            records = list(evidence.get("records", []))
            if not records and evidence.get("content"):
                records.extend(self._inline_records(evidence["content"], identifiers))
            for record in records:
                if not isinstance(record, dict) or not any(normalized(value) in identifiers for _, value in values_in(record)):
                    continue
                event_time = parse_time(field_value(record, {"event_time", "timestamp", "updated_at", "captured_at", "observed_at", "created_at"}))
                if audit_cutoff and event_time and event_time > audit_cutoff:
                    continue
                resource = str(record.get("resource_id", record.get("file_id", record.get("activity_id", ""))))
                if not resource:
                    continue
                category = self._category(record, resource)
                rule = self.rules.get(category, {})
                treatment = str(rule.get("required_action", "")).upper()
                system = str(record.get("system_id", record.get("origin_system", record.get("source_system", ""))))
                system = system or {
                    "USER_PROFILE": "account_service", "SEARCH_INDEX_ENTRY": "search_service",
                    "ANALYTICS_PROFILE": "analytics_platform", "PRODUCT_TELEMETRY": "analytics_platform",
                    "SUPPORT_MESSAGE": "support_platform", "SUPPORT_ATTACHMENT": "support_platform",
                    "USER_EXPORT": "export_service", "BACKUP_ARCHIVE": "backup_service",
                    "ACCOUNT_TOMBSTONE": "identity_service", "SECURITY_AUDIT_LOG": "security_service",
                }.get(category, "unknown")
                state = self._state(record)
                active = state in {"ACTIVE", "ENABLED", "RUNNING", "RESTORABLE", "AVAILABLE"}
                has_direct_identifier = any(
                    key in {"email", "phone", "full_name", "name", "email_hash"} and value not in (None, "")
                    for key, value in values_in(record)
                )
                operation = None
                step_state = "PRESENT"
                if "data_flow" in resource.casefold() and active:
                    operation, step_state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
                elif category == "BACKUP_ARCHIVE" and active:
                    operation, step_state = "REPORT_RESTORE_RISK", "ACTIVE"
                elif treatment == "RETAIN":
                    safe_checks.append((system, resource, "VERIFY_RECORD_PRESENT", "PRESENT", evidence["file_id"], category))
                    continue
                elif treatment == "DELETE" and state not in {"ABSENT", "NOT_FOUND", "DELETED"}:
                    operation = "REPORT_REMAINING_RECORD"
                elif treatment in {"REDACT", "ANONYMIZE"} and has_direct_identifier:
                    operation = "REPORT_EXPOSED_PII"

                if operation:
                    excerpt = " ".join(
                        str(value) for key, value in record.items()
                        if key.casefold() in {"state", "status", "category", "event_type", "operation_result"}
                    )[:240]
                    reason, recommended = explain_finding(operation, system, resource, category, treatment)
                    findings.append({
                        "phase": "FINDING", "system_id": system, "resource_id": resource,
                        "operation": operation, "state": step_state, "evidence_id": evidence["file_id"],
                        "data_category": category, "evidence_excerpt": excerpt, "policy_action": treatment,
                        "reason": reason, "recommended_action": recommended, "_record": record,
                    })
                elif treatment in {"DELETE", "REDACT", "ANONYMIZE"}:
                    operation_by_treatment = {
                        "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
                        "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
                        "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
                    }
                    operation, state_out = operation_by_treatment[treatment]
                    safe_checks.append((system, resource, operation, state_out, evidence["file_id"], category))

        seen: set[tuple[Any, ...]] = set()
        deduped = []
        for finding in findings:
            key = tuple(finding.get(name) for name in ("system_id", "resource_id", "operation", "evidence_id"))
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        return deduped, safe_checks
