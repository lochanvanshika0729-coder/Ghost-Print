"""Current and historical identity resolution for deletion requests."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

import pandas as pd


IDENTITY_FIELDS = ("email", "name", "phone", "email_hash")


def _records(frame: pd.DataFrame | Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(frame, pd.DataFrame):
        return frame.to_dict(orient="records")
    return list(frame)


def _norm(value: Any) -> str:
    return str(value if value is not None else "").strip().casefold()


def _time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def resolve_identity(
    request: dict[str, Any],
    identities: pd.DataFrame | Iterable[dict[str, Any]],
    audit_history: pd.DataFrame | Iterable[dict[str, Any]],
) -> tuple[dict[str, Any], set[str], str]:
    """Return the unique person, current/historical identifiers, and status.

    Audit-log changes after the request's audit_at cutoff are excluded. A
    non-unique match is never merged with another person.
    """
    email = _norm(request.get("email"))
    cutoff = _time(request.get("audit_at"))
    histories = _records(audit_history)
    candidates: list[tuple[dict[str, Any], set[str], list[dict[str, Any]], dict[str, set[str]]]] = []

    for person in _records(identities):
        user_id = str(person.get("user_id", ""))
        history: list[dict[str, Any]] = []
        for event in histories:
            if str(event.get("user_id", "")) != user_id:
                continue
            event_time = _time(event.get("event_time"))
            if cutoff and event_time and event_time > cutoff:
                continue
            history.append(event)

        snapshot_time = _time(person.get("updated_at"))
        snapshot_in_scope = not cutoff or not snapshot_time or snapshot_time <= cutoff
        identifiers: set[str] = set()
        identifier_values: dict[str, set[str]] = {key: set() for key in IDENTITY_FIELDS}
        if snapshot_in_scope:
            for key in IDENTITY_FIELDS:
                value = str(person.get(key, "") or "").strip()
                if value:
                    identifiers.add(_norm(value))
                    identifier_values[key].add(value)
        if user_id:
            identifiers.add(_norm(user_id))

        for event in history:
            field = str(event.get("field_name", "")).casefold()
            if field not in IDENTITY_FIELDS:
                continue
            for key in ("old_value", "new_value"):
                value = str(event.get(key, "") or "").strip()
                if value:
                    identifiers.add(_norm(value))
                    identifier_values[field].add(value)
        if email and email in identifiers:
            if user_id:
                identifier_values["user_id"] = {user_id}
            candidates.append((person, identifiers, history, identifier_values))

    if len(candidates) != 1:
        return {}, set(), "AMBIGUOUS" if candidates else "UNRESOLVED"

    person, identifiers, history, identifier_values = candidates[0]
    current_email = str(person.get("email", "") or "").strip()
    historical_values: dict[str, set[str]] = {key: set() for key in IDENTITY_FIELDS}
    for event in history:
        field = str(event.get("field_name", "")).casefold()
        if field in IDENTITY_FIELDS:
            historical_values[field].update(
                str(event.get(key, "") or "").strip()
                for key in ("old_value", "new_value")
                if str(event.get(key, "") or "").strip()
            )
    if current_email:
        historical_values["email"].discard(current_email)

    identity = {
        "user_id": person.get("user_id"),
        "current_email": current_email or None,
        "historical_emails": sorted(historical_values["email"], key=str.casefold),
        "historical_identifiers": {
            key: sorted(values, key=str.casefold)
            for key, values in historical_values.items() if values
        },
        "known_identifiers": sorted(
            {str(value).strip() for values in identifier_values.values() for value in values if value}, key=str.casefold
        ),
        "resolution_status": "RESOLVED",
        "evidence_ids": sorted({str(event.get("audit_id")) for event in history if event.get("audit_id")}),
    }
    return identity, identifiers, "RESOLVED"
