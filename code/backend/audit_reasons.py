"""Evidence-grounded explanations for deletion audit outcomes."""

from __future__ import annotations

from collections.abc import Mapping


UNKNOWN_REASON = (
    "The audit is incomplete, but its specific cause cannot be determined from the available evidence. "
    "No unverified state is treated as proof that deletion succeeded or that data remains."
)


def explain_audit_status(status: str, cause: str = "", **details) -> str:
    """Describe an incomplete audit using only facts supplied by the audit engine.

    Complete and non-deletion decisions intentionally receive no incomplete reason.
    """
    if status != "INCOMPLETE":
        return ""

    if cause == "IDENTITY_AMBIGUOUS":
        return ("The deletion request was recognized, but multiple identity profiles matched the supplied "
                "identifier. The audit could not safely attribute resources to one person.")
    if cause == "IDENTITY_UNRESOLVED":
        return ("The deletion request was recognized, but no identity profile matched the supplied identifier. "
                "Resource evidence could not be attributed to the requester.")
    if cause == "FINDINGS":
        findings = [item for item in details.get("findings", []) if isinstance(item, Mapping)]
        supported = [item for item in findings if item.get("evidence_id") and item.get("reason")]
        if not supported:
            return UNKNOWN_REASON
        statements = []
        for item in supported:
            target = " / ".join(str(item.get(key, "")).strip() for key in ("system_id", "resource_id")
                                if item.get(key))
            ref = str(item["evidence_id"])
            statement = str(item["reason"]).strip()
            statements.append(f"{target}: {statement} (evidence {ref})" if target else f"{statement} (evidence {ref})")
        return "The audit is incomplete because the following evidence-backed policy issues remain: " + " ".join(statements)
    if cause == "RESOURCE_ID_MISSING":
        refs = ", ".join(details.get("evidence_ids", []))
        citation = f" Evidence: {refs}." if refs else ""
        return ("The audit matched subject-linked evidence, but the matching record did not contain a resource "
                "identifier. The affected resource therefore could not be located or independently verified." + citation)
    if cause == "POLICY_UNAVAILABLE":
        category = str(details.get("category", "")).strip() or "the matched data category"
        refs = ", ".join(details.get("evidence_ids", []))
        citation = f" Evidence: {refs}." if refs else ""
        return (f"The audit found a subject-linked {category} record, but no applicable deletion rule was available "
                "to determine its required final treatment." + citation)
    if cause == "RETAINED_RECORDS_ONLY":
        refs = ", ".join(details.get("evidence_ids", []))
        citation = f" The records are supported by evidence {refs}." if refs else ""
        return ("The audit found policy-required retained records, but no evidence-backed deletion, redaction, "
                "or anonymization check. Retention evidence alone does not verify deletion treatment." + citation)
    if cause == "NO_MATCHING_EVIDENCE":
        cutoff = str(details.get("audit_at", "")).strip()
        at = f" by the {cutoff} audit cutoff" if cutoff else " by the audit cutoff"
        return ("The requester identity was resolved, but no readable subject-linked resource evidence established "
                "which resources require deletion or whether their required final state was reached" + at +
                ". The specific cause cannot be determined from the available evidence, and deletion remains unverified.")
    if cause == "VERIFICATION_INSUFFICIENT":
        refs = ", ".join(details.get("evidence_ids", []))
        citation = f" Related evidence: {refs}." if refs else ""
        return ("The deletion request and identity were recognized, but the available matching records did not "
                "establish a policy-compliant terminal state by the audit cutoff. Deletion remains unverified." + citation)

    return UNKNOWN_REASON
