import sqlite3

import pytest

from backend.engine import AuditEngine, _safe_sql_snapshot, parse_time


@pytest.mark.parametrize("text", [
    "Please erase my account and the personal data linked to it.",
    "Please permanently delete this account.",
    "Je demande la suppression définitive de mon compte.",
    "Intenté eliminar mi cuenta.",
    "このアカウントの削除を依頼します。",
])
def test_explicit_deletion_requests_are_recognized(text):
    assert AuditEngine._deletion_request(text)


@pytest.mark.parametrize("text", [
    "Please export my account data.",
    "Update my email address, but do not delete the account.",
    "Unsubscribe me from marketing emails.",
])
def test_non_deletion_requests_are_not_authorized(text):
    assert not AuditEngine._deletion_request(text)


def test_timestamps_are_normalized_to_utc():
    assert parse_time("2026-09-01T10:00:00+02:00").isoformat() == "2026-09-01T08:00:00+00:00"


def test_sql_snapshot_reader_reads_only_in_memory_table_data():
    rows = _safe_sql_snapshot("CREATE TABLE records(resource_id TEXT, state TEXT); INSERT INTO records VALUES('r1','ACTIVE');")
    assert rows == [{"resource_id":"r1", "state":"ACTIVE", "collection_name":"records"}]


def test_sql_snapshot_reader_allows_snapshot_pragmas_and_indexes():
    rows = _safe_sql_snapshot("PRAGMA foreign_keys=ON; CREATE TABLE records(resource_id TEXT PRIMARY KEY, state TEXT); CREATE INDEX idx_records_state ON records(state); INSERT INTO records VALUES('r1','ACTIVE');")
    assert rows == [{"resource_id":"r1", "state":"ACTIVE", "collection_name":"records"}]


def test_sql_snapshot_reader_denies_external_database_attach():
    with pytest.raises(sqlite3.DatabaseError):
        _safe_sql_snapshot("ATTACH DATABASE '/tmp/unsafe.db' AS unsafe;")
