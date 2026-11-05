from backend.audit_reasons import UNKNOWN_REASON, explain_audit_status
from backend.engine import AuditEngine


def test_incomplete_without_matching_evidence_says_deletion_is_unverified():
    explanation = explain_audit_status(
        "INCOMPLETE", "NO_MATCHING_EVIDENCE", audit_at="2026-09-01T12:00:00Z"
    )
    assert "no readable subject-linked resource evidence" in explanation
    assert "specific cause cannot be determined" in explanation
    assert "unverified" in explanation


def test_insufficient_verification_cites_only_supplied_evidence_ids():
    explanation = explain_audit_status(
        "INCOMPLETE", "VERIFICATION_INSUFFICIENT", evidence_ids=["evidence_12"]
    )
    assert "terminal state" in explanation
    assert "evidence_12" in explanation
    assert "evidence_99" not in explanation


def test_missing_resource_information_identifies_the_evidence_gap():
    explanation = explain_audit_status(
        "INCOMPLETE", "RESOURCE_ID_MISSING", evidence_ids=["evidence_4"]
    )
    assert "resource identifier" in explanation
    assert "evidence_4" in explanation
    assert "independently verified" in explanation


def test_unknown_cause_is_explicit_without_claiming_a_specific_failure():
    explanation = explain_audit_status("INCOMPLETE", "UNCLASSIFIED")
    assert explanation == UNKNOWN_REASON
    assert "cannot be determined" in explanation


def test_complete_audit_has_no_incomplete_reason():
    assert explain_audit_status("COMPLETE", "NO_MATCHING_EVIDENCE") == ""


def test_not_applicable_audit_has_no_incomplete_reason():
    assert explain_audit_status("NOT_APPLICABLE", "IDENTITY_UNRESOLVED") == ""


def test_finding_without_evidence_reference_does_not_create_a_specific_claim():
    explanation = explain_audit_status(
        "INCOMPLETE",
        "FINDINGS",
        findings=[{
            "system_id": "made_up_system",
            "resource_id": "made_up_resource",
            "reason": "A record remains.",
            "evidence_id": "",
        }],
    )
    assert explanation == UNKNOWN_REASON
    assert "made_up_system" not in explanation
    assert "made_up_resource" not in explanation


def _engine_with(records):
    engine = AuditEngine.__new__(AuditEngine)
    engine.rules = {"USER_PROFILE": {"required_action": "DELETE"}}
    engine.manifest = [{"file_id": "evidence_1", "file_path": "records/example.json", "captured_at": "2026-09-01T11:00:00Z"}]
    engine.evidence = ([{"file_id": "evidence_1", "captured_at": "2026-09-01T11:00:00Z",
                         "records": records, "content": "", "error": None}] if records else [])
    engine._resolve = lambda request: ({"user_id": "user_1", "resolution_status": "RESOLVED"},
                                       {"user_1", "person@example.com"}, "RESOLVED")
    return engine


def _request(text="Please delete my account"):
    return {"case_id": "case_test", "email": "person@example.com",
            "request_text": text, "audit_at": "2026-09-01T12:00:00Z"}


def test_engine_surfaces_missing_resource_reason_from_matched_record():
    engine = _engine_with([{"email": "person@example.com", "data_category": "USER_PROFILE", "state": "PRESENT"}])
    result = engine.analyze(_request())
    assert result["deletion_status"] == "INCOMPLETE"
    assert "resource identifier" in result["explanation"]
    assert "evidence_1" in result["explanation"]


def test_engine_surfaces_evidence_backed_finding_reason():
    engine = _engine_with([{"email": "person@example.com", "resource_id": "account_1",
                            "data_category": "USER_PROFILE", "state": "PRESENT"}])
    result = engine.analyze(_request())
    assert result["deletion_status"] == "INCOMPLETE"
    assert "account_service / account_1" in result["explanation"]
    assert "evidence_1" in result["explanation"]


def test_complete_and_not_applicable_engine_classifications_remain_unchanged():
    engine = _engine_with([{"email": "person@example.com", "resource_id": "account_1",
                            "data_category": "USER_PROFILE", "state": "ABSENT"}])
    complete = engine.analyze(_request())
    not_applicable = engine.analyze(_request("Please export my account data"))
    assert complete["deletion_status"] == "COMPLETE"
    assert "incomplete" not in complete["explanation"].casefold()
    assert not_applicable["deletion_status"] == "NOT_APPLICABLE"
    assert "incomplete" not in not_applicable["explanation"].casefold()
