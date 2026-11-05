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

    def _resolve(self, request: dict[str, str]) -> tuple[dict[str, Any], set[str], str]:
        email = normalized(request.get("email"))
        cutoff = parse_time(request.get("audit_at"))
        candidates = []
        for person in self.identities:
            history = [x for x in self.audit_log if x.get("user_id") == person.get("user_id") and
                       (not cutoff or not parse_time(x.get("event_time")) or parse_time(x.get("event_time")) <= cutoff)]
            snapshot_time = parse_time(person.get("updated_at"))
            ids = {normalized(person.get(k)) for k in ("email", "name", "phone", "email_hash")
                   if person.get(k) and (not cutoff or not snapshot_time or snapshot_time <= cutoff)}
            if person.get("user_id"):
                ids.add(normalized(person["user_id"]))
            for event in history:
                if event.get("field_name", "").casefold() in {"email", "name", "phone", "email_hash"}:
                    ids.update(normalized(event.get(k)) for k in ("old_value", "new_value") if event.get(k))
            if email in ids:
                candidates.append((person, ids, history))
        if len(candidates) != 1:
            return {}, set(), "AMBIGUOUS" if candidates else "UNRESOLVED"
        person, ids, history = candidates[0]
        history_emails = sorted({e.get("old_value") for e in history if e.get("field_name", "").casefold() == "email" and e.get("old_value")})
        return {"user_id": person.get("user_id"), "current_email": person.get("email"),
                "historical_emails": history_emails, "resolution_status": "RESOLVED",
                "evidence_ids": [e.get("audit_id") for e in history if e.get("audit_id")]}, ids, "RESOLVED"

    @staticmethod
    def _deletion_request(text: str) -> bool:
        t = normalized(text)
        denied = re.search(r"\b(do not|don't|never|without)\s+(delete|erase|remove)|\bnot (a )?deletion\b", t)
        action = re.search(r"\b(delet\w*|eras\w*|remov\w*|clos\w*|purge\w*|wip\w*|elimin\w*|suppress\w*)\b|right to be forgotten|(?:削除|消去|抹消)", t)
        other = re.search(r"\b(access|export|correct|update|rectify|unsubscribe|marketing opt.?out|password reset)\b", t)
        return bool(action and not denied and not other)

    def _category(self, record: dict[str, Any], resource: str) -> str:
        category = str(field_value(record,{"data_category","category"}) or "").upper()
        if category in self.rules:
            return category
        context = (str(record.get("collection_name", "")) + " " + resource).casefold()
        patterns = [("tombstone", "ACCOUNT_TOMBSTONE"), ("security_audit", "SECURITY_AUDIT_LOG"),
                    ("legal_hold", "LEGAL_HOLD_RECORD"), ("backup", "BACKUP_ARCHIVE"), ("archive", "BACKUP_ARCHIVE"),
                    ("secondary_identifier", "SECONDARY_IDENTIFIER"), ("cache", "CACHE_ENTRY"),
                    ("analytics", "ANALYTICS_PROFILE"), ("telemetry", "PRODUCT_TELEMETRY"),
                    ("attachment", "SUPPORT_ATTACHMENT"), ("support", "SUPPORT_MESSAGE"),
                    ("search", "SEARCH_INDEX_ENTRY"), ("index", "SEARCH_INDEX_ENTRY"), ("export", "USER_EXPORT"), ("marketing", "MARKETING_PROFILE"),
                    ("email_delivery", "EMAIL_DELIVERY_LOG"), ("account", "USER_PROFILE")]
        for token, result in patterns:
            if token in context:
                return result
        return "UNKNOWN"

    @staticmethod
    def _state(record: dict[str, Any]) -> str:
        value=field_value(record,{"record_state","state","status","account_status","operation_result","restore_status"})
        if value not in (None, ""):
            return str(value).upper()
        return "UNKNOWN"

    def _matches(self, record: dict[str, Any], identifiers: set[str]) -> bool:
        return any(normalized(v) in identifiers for _, v in values_in(record))

    def analyze(self, request: dict[str, str]) -> dict[str, Any]:
        case_id = request["case_id"]
        if not self._deletion_request(request.get("request_text", "")):
            return self._make_result(case_id, "NOT_APPLICABLE", request, {}, [], [], "Request text does not authorize deletion.")
        identity, identifiers, resolved = self._resolve(request)
        if resolved != "RESOLVED":
            return self._make_result(case_id, "INCOMPLETE", request, identity, [], [], "Identity could not be resolved uniquely; no records were merged.")
        cutoff = parse_time(request.get("audit_at")); findings=[]; safe_checks=[]
        for evidence in self.evidence:
            captured = parse_time(evidence.get("captured_at"))
            if evidence.get("error") or (cutoff and captured and captured > cutoff):
                continue
            records = list(evidence.get("records", []))
            if not records and evidence.get("content"):
                for line in evidence["content"].splitlines():
                    if not any(identifier and identifier in normalized(line) for identifier in identifiers):
                        continue
                    match = re.search(r"\b(?:account|search|support|analytics|export|backup|tombstone|data_flow|audit_record)_[0-9][\w-]*\b", line, re.I)
                    if match:
                        inline={"resource_id":match.group(),"line":line}
                        email_match=re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",line)
                        if email_match:inline["email"]=email_match.group()
                        state_match=re.search(r"\b(NOT_FOUND|ABSENT|DELETED|REDACTED|ANONYMIZED|ANONYMISED|ACTIVE|ENABLED|RUNNING|FOUND|PRESENT|IDENTIFIABLE|BLOCKED|DISABLED)\b",line,re.I)
                        if state_match:inline["state"]=state_match.group(1).upper()
                        records.append(inline)
            for record in records:
                if not isinstance(record, dict) or not self._matches(record, identifiers):
                    continue
                too_late = False
                event_time = parse_time(field_value(record,{"event_time","timestamp","updated_at","captured_at","observed_at","created_at"}))
                if cutoff and event_time and event_time > cutoff:
                    too_late = True
                if too_late:
                    continue
                resource = str(record.get("resource_id", record.get("file_id", record.get("activity_id", ""))))
                if not resource:
                    continue
                category = self._category(record, resource)
                rule = self.rules.get(category, {})
                treatment = str(rule.get("required_action", "")).upper()
                system = str(record.get("system_id", record.get("origin_system", record.get("source_system", ""))))
                system = system or {"USER_PROFILE":"account_service", "SEARCH_INDEX_ENTRY":"search_service", "ANALYTICS_PROFILE":"analytics_platform",
                                    "PRODUCT_TELEMETRY":"analytics_platform", "SUPPORT_MESSAGE":"support_platform", "SUPPORT_ATTACHMENT":"support_platform",
                                    "USER_EXPORT":"export_service", "BACKUP_ARCHIVE":"backup_service", "ACCOUNT_TOMBSTONE":"identity_service",
                                    "SECURITY_AUDIT_LOG":"security_service"}.get(category,"unknown")
                state=self._state(record)
                active=state in {"ACTIVE","ENABLED","RUNNING","RESTORABLE","AVAILABLE"}
                pii=any(k in {"email","phone","full_name","name","email_hash"} and v not in (None,"") for k,v in values_in(record))
                operation=None;step_state="PRESENT"
                if "data_flow" in resource.casefold() and active:
                    operation,step_state="REPORT_ACTIVE_DATA_FLOW","ACTIVE"
                elif category=="BACKUP_ARCHIVE" and active:
                    operation,step_state="REPORT_RESTORE_RISK","ACTIVE"
                elif treatment=="RETAIN":
                    safe_checks.append((system,resource,"VERIFY_RECORD_PRESENT","PRESENT",evidence["file_id"],category))
                    continue
                elif treatment=="DELETE" and state not in {"ABSENT","NOT_FOUND","DELETED"}:
                    operation="REPORT_REMAINING_RECORD"
                elif treatment in {"REDACT","ANONYMIZE"} and pii:
                    operation="REPORT_EXPOSED_PII"
                if operation:
                    excerpt=" ".join(str(v) for k,v in record.items() if k.casefold() in {"state","status","category","event_type","operation_result"})[:240]
                    reason,recommended=explain_finding(operation,system,resource,category,treatment)
                    findings.append({"phase":"FINDING","system_id":system,"resource_id":resource,"operation":operation,"state":step_state,
                                     "evidence_id":evidence["file_id"],"data_category":category,"evidence_excerpt":excerpt,
                                     "policy_action":treatment,"reason":reason,"recommended_action":recommended,"_record":record})
                elif treatment in {"DELETE","REDACT","ANONYMIZE"}:
                    op={"DELETE":"VERIFY_RECORD_ABSENT","REDACT":"VERIFY_RECORD_REDACTED","ANONYMIZE":"VERIFY_RECORD_ANONYMIZED"}[treatment]
                    state_out={"DELETE":"ABSENT","REDACT":"REDACTED","ANONYMIZE":"ANONYMIZED"}[treatment]
                    safe_checks.append((system,resource,op,state_out,evidence["file_id"],category))
        findings=self._dedupe(findings)
        steps=list(findings)
        if findings:
            for f in findings:
                if f["operation"]=="REPORT_ACTIVE_DATA_FLOW": rem,state,verify="DISABLE_DATA_FLOW","DISABLED","VERIFY_DATA_FLOW_DISABLED"
                elif f["operation"]=="REPORT_RESTORE_RISK": rem,state,verify="BLOCK_RESTORE","BLOCKED","VERIFY_RESTORE_BLOCKED"
                else:
                    treatment=self.rules.get(f["data_category"],{}).get("required_action","DELETE").upper()
                    rem={"DELETE":"DELETE_RECORD","REDACT":"REDACT_RECORD","ANONYMIZE":"ANONYMIZE_RECORD"}.get(treatment,"DELETE_RECORD")
                    state={"DELETE_RECORD":"ABSENT","REDACT_RECORD":"REDACTED","ANONYMIZE_RECORD":"ANONYMIZED"}[rem]
                    verify={"DELETE_RECORD":"VERIFY_RECORD_ABSENT","REDACT_RECORD":"VERIFY_RECORD_REDACTED","ANONYMIZE_RECORD":"VERIFY_RECORD_ANONYMIZED"}[rem]
                steps.extend([{"phase":"REMEDIATION","system_id":f["system_id"],"resource_id":f["resource_id"],"operation":rem,"state":state,"evidence_id":""},
                              {"phase":"VERIFICATION","system_id":f["system_id"],"resource_id":f["resource_id"],"operation":verify,"state":state,"evidence_id":""}])
            status="INCOMPLETE"
        elif safe_checks:
            deletion_checks=[x for x in safe_checks if x[2] in {"VERIFY_RECORD_ABSENT","VERIFY_RECORD_REDACTED","VERIFY_RECORD_ANONYMIZED"}]
            if not deletion_checks:
                return self._make_result(case_id,"INCOMPLETE",request,identity,[],[],"Evidence supports retained records but does not verify deletion treatment.")
            steps=[{"phase":"VERIFICATION","system_id":s,"resource_id":r,"operation":o,"state":st,"evidence_id":eid} for s,r,o,st,eid,_ in safe_checks]
            status="COMPLETE"
        else:
            return self._make_result(case_id,"INCOMPLETE",request,identity,[],[],"No policy-compliant verification evidence was found by the audit cutoff.")
        steps.sort(key=lambda s:(PHASE_ORDER[s["phase"]],OPERATION_ORDER.index(s["operation"]),s["system_id"],s["resource_id"]))
        for number, step in enumerate(steps,1): step["step_no"]=number
        clean=[{k:v for k,v in s.items() if k not in {"data_category","evidence_excerpt","_record"}} for s in steps]
        affected=", ".join(sorted({f["system_id"] for f in findings}))
        summary=(f"The audit is incomplete: {len(findings)} evidence-backed issue(s) were found in {affected or 'the supplied records'}. Review each reason, policy treatment, and evidence reference below." if findings else
                 f"No policy violation was found in the matched evidence; {len(safe_checks)} supported observations are listed in the verification steps.")
        return self._make_result(case_id,status,request,identity,clean,findings,summary)

    @staticmethod
    def _dedupe(items):
        out=[];seen=set()
        for item in items:
            key=tuple(item.get(k) for k in ("system_id","resource_id","operation","evidence_id"))
            if key not in seen:seen.add(key);out.append(item)
        return out

    def _make_result(self, case_id, status, request, identity, steps, findings, explanation):
        evidence_by_id={item.get("file_id"):item for item in self.manifest}
        node_map={}
        def add_node(system, resource, state, evidence_id, category="", record=None):
            system=str(system or "unknown"); resource=str(resource or "")
            if not resource or not evidence_id:
                return
            node_id=f"{system}::{resource}"; node=node_map.get(node_id)
            if node is None:
                node={"id":node_id,"system_id":system,"resource_id":resource,
                      "resource_name":str((record or {}).get("resource_name") or (record or {}).get("resource_label") or category or "Observed resource")[:120],
                      "resource_type":str(category or (record or {}).get("record_type") or "Not available")[:80],
                      "presence_status":str(state or "UNKNOWN").upper(),"verification_status":"UNKNOWN",
                      "verification_operation":"","evidence_ids":[],"evidence":[],"last_observed_at":"",
                      "audit_status":status,"audit_cutoff":request.get("audit_at", ""),"reason":""}
                node_map[node_id]=node
            elif state and node["presence_status"]=="UNKNOWN":
                node["presence_status"]=str(state).upper()
            if evidence_id not in node["evidence_ids"]:
                node["evidence_ids"].append(evidence_id)
                file=evidence_by_id.get(evidence_id,{})
                filename=Path(file.get("file_path", "")).name
                node["evidence"].append({"evidence_id":evidence_id,
                    "description":" · ".join(x for x in (file.get("origin", ""),filename) if x) or "Evidence metadata unavailable",
                    "file_path":file.get("file_path", ""),"observed_at":file.get("captured_at", "")})
            record=record or {}
            observed=next((str(record.get(k)) for k in ("observed_at","recorded_at","event_time","timestamp","updated_at") if record.get(k)),"")
            observed=observed or str(evidence_by_id.get(evidence_id,{}).get("captured_at", ""))
            if observed and (not node["last_observed_at"] or observed>node["last_observed_at"]):
                node["last_observed_at"]=observed
            verification=next((s for s in steps if s.get("phase")=="VERIFICATION" and s.get("system_id")==system and s.get("resource_id")==resource and s.get("evidence_id") and s.get("operation","").startswith("VERIFY_")),None)
            pending=any(s.get("phase")=="REMEDIATION" and s.get("system_id")==system and s.get("resource_id")==resource for s in steps)
            if verification:
                node["verification_status"]="VERIFIED";node["verification_operation"]=verification["operation"]
                if verification.get("state"):node["presence_status"]=verification["state"]
            elif pending or any(f.get("system_id")==system and f.get("resource_id")==resource for f in findings):
                node["verification_status"]="PENDING"
            else:
                node["verification_status"]="EVIDENCE_UNAVAILABLE" if not node["evidence_ids"] else "UNKNOWN"

        relations=[]
        for finding in findings:
            record=finding.get("_record",{})
            add_node(finding.get("system_id"),finding.get("resource_id"),finding.get("state"),finding.get("evidence_id"),finding.get("data_category",""),record)
            node=node_map.get(f"{finding.get('system_id') or 'unknown'}::{finding.get('resource_id') or ''}")
            if node and finding.get("reason"):node["reason"]=finding["reason"]
            source=record.get("source_resource_id") or record.get("from_resource_id") or record.get("parent_resource_id")
            target=record.get("target_resource_id") or record.get("to_resource_id") or record.get("child_resource_id")
            relation=record.get("relationship_type") or record.get("relation_type") or record.get("relationship") or record.get("transfer_type") or record.get("event_type")
            if source and target and isinstance(relation,str) and relation.strip():
                relations.append({"source_resource_id":str(source),"target_resource_id":str(target),"source_system_id":record.get("source_system_id") or record.get("source_system"),"target_system_id":record.get("target_system_id") or record.get("target_system"),"type":relation.strip().upper()[:80],"evidence_id":finding.get("evidence_id"),"allow_self":record.get("allow_self_relationship") is True})
        for step in steps:
            if step.get("evidence_id"):
                add_node(step.get("system_id"),step.get("resource_id"),step.get("state"),step.get("evidence_id"))
        by_resource={}
        for node in node_map.values():by_resource.setdefault(node["resource_id"],[]).append(node)
        def endpoint(resource,system):
            if system:
                candidate=node_map.get(f"{system}::{resource}")
                if candidate:return candidate["id"]
            options=by_resource.get(resource,[])
            return options[0]["id"] if len(options)==1 else None
        edges={}
        for rel in relations:
            source=endpoint(rel["source_resource_id"],rel["source_system_id"]);target=endpoint(rel["target_resource_id"],rel["target_system_id"])
            if not source or not target or (source==target and not rel["allow_self"]):continue
            edge={"id":"|".join((source,target,rel["type"],rel["evidence_id"] or "")),"source":source,"target":target,"type":rel["type"],"evidence_id":rel["evidence_id"] or "","description":evidence_by_id.get(rel["evidence_id"],{}).get("file_path","Evidence metadata unavailable")}
            edges[edge["id"]]=edge
        nodes=sorted(node_map.values(),key=lambda n:(n["system_id"],n["resource_id"]))
        graph_edges=sorted(edges.values(),key=lambda e:(e["source"],e["target"],e["type"]))
        graph_data={"case_id":case_id,"audit_status":status,"audit_cutoff":request.get("audit_at", ""),"nodes":nodes,"edges":graph_edges,
                    "relationship_status":"Evidence-supported relationships found" if graph_edges else "No verified resource-to-resource relationships were found for this case."}
        risk=self.risk(steps)
        safe_findings=[{k:v for k,v in finding.items() if k!="_record"} for finding in findings]
        return {"case_id":case_id,"deletion_status":status,"request":request,"identity":identity,"steps":steps,"findings":safe_findings,
                "explanation":explanation,"graph":graph_data,"risk_level":risk}

    @staticmethod
    def risk(steps):
        findings=[s for s in steps if s.get("phase")=="FINDING"]
        if not findings:return "LOW" if steps else "UNKNOWN"
        flows=sum(s["operation"]=="REPORT_ACTIVE_DATA_FLOW" for s in findings)
        restores=sum(s["operation"]=="REPORT_RESTORE_RISK" for s in findings)
        systems=len({s["system_id"] for s in findings})
        score=min(100,len(findings)*4+flows*12+restores*16+systems*3)
        return "CRITICAL" if score>=75 else "HIGH" if score>=50 else "MEDIUM" if score>=25 else "LOW"

    def cases(self):
        if self.cache:return list(self.cache.values())
        with SessionLocal() as db:
            saved={r.case_id:r for r in db.scalars(select(Investigation)).all()}
            for request in self.requests:
                case_id=request["case_id"]
                if case_id in saved:
                    row=saved[case_id]
                    result={"case_id":case_id,"deletion_status":row.deletion_status,"risk_level":row.risk_level,"request":row.request,
                            "identity":row.identity,"steps":row.steps,"findings":row.findings,"graph":row.graph,"explanation":row.explanation}
                else:
                    result=self.analyze(request)
                    db.add(Investigation(case_id=case_id,deletion_status=result["deletion_status"],risk_level=result["risk_level"],request=request,
                                         identity=result["identity"],steps=result["steps"],findings=result["findings"],graph=result["graph"],explanation=result["explanation"]))
                self.cache[case_id]=result
            db.commit()
        return list(self.cache.values())

    def get(self, case_id):
        return next((x for x in self.cases() if x["case_id"]==case_id),None)

    def dashboard(self):
        cases=self.cases();statuses={s:sum(c["deletion_status"]==s for c in cases) for s in ("COMPLETE","INCOMPLETE","NOT_APPLICABLE")}
        findings=[s for c in cases for s in c["steps"] if s["phase"]=="FINDING"];systems={}
        for s in findings:systems[s["system_id"]]=systems.get(s["system_id"],0)+1
        risks={r:sum(c["risk_level"]==r for c in cases) for r in ("LOW","MEDIUM","HIGH","CRITICAL","UNKNOWN")}
        recent=sorted(cases,key=lambda x:x["request"].get("requested_at",""),reverse=True)[:10]
        return {"total_requests":len(cases),"completed":statuses["COMPLETE"],"incomplete":statuses["INCOMPLETE"],"not_applicable":statuses["NOT_APPLICABLE"],
                "high_risk_cases":sum(c["risk_level"] in {"HIGH","CRITICAL"} for c in cases),"active_flows":sum(s["operation"]=="REPORT_ACTIVE_DATA_FLOW" for s in findings),
                "restore_risks":sum(s["operation"]=="REPORT_RESTORE_RISK" for s in findings),"by_system":systems,"risk_distribution":risks,"recent":recent}

    def dataset(self):
        files=[{"file_id":e.get("file_id"),"file_path":e.get("file_path"),"captured_at":e.get("captured_at"),"readable":not e.get("error"),"error":e.get("error")} for e in self.evidence]
        return {"dataset_id":"official-challenge","request_count":len(self.requests),"evidence_count":len(files),"manifest":files,
                "missing":[x for x in files if not x["readable"]],"columns":{"deletion_requests":list(self.requests[0]) if self.requests else []}}

    def export_csv(self):
        import csv
        from io import StringIO
        out=StringIO(newline="");writer=csv.writer(out,lineterminator="\n");writer.writerow(["case_id","deletion_status","steps_json"])
        for case in sorted(self.cases(),key=lambda x:x["case_id"]):
            writer.writerow([case["case_id"],case["deletion_status"],json.dumps(case["steps"],ensure_ascii=False,separators=(",",":"))])
        return out.getvalue()

    def store_upload(self, filename, content, content_type):
        suffix=Path(filename).suffix.casefold()
        if suffix not in UPLOAD_TYPES:raise ValueError("Unsupported file type")
        if not content or len(content)>MAX_FILE_BYTES:raise ValueError("File is empty or larger than the 10 MiB limit")
        if suffix==".pdf" and not content.startswith(b"%PDF-"):raise ValueError("File content does not match PDF format")
        if suffix==".png" and not content.startswith(b"\x89PNG\r\n\x1a\n"):raise ValueError("File content does not match PNG format")
        if suffix in {".jpg", ".jpeg"} and not content.startswith(b"\xff\xd8\xff"):raise ValueError("File content does not match JPEG format")
        if suffix==".webp" and not (content.startswith(b"RIFF") and content[8:12]==b"WEBP"):raise ValueError("File content does not match WebP format")
        if suffix==".json":
            try:json.loads(content.decode("utf-8"))
            except (UnicodeDecodeError,json.JSONDecodeError) as exc:raise ValueError("Invalid JSON upload") from exc
        if suffix in {".txt", ".log", ".csv", ".sql"}:
            try:content.decode("utf-8")
            except UnicodeDecodeError as exc:raise ValueError("Text upload must be UTF-8") from exc
        safe=re.sub(r"[^A-Za-z0-9._-]","_",Path(filename).name)[:160];digest=hashlib.sha256(content).hexdigest();file_id=f"upload_{digest[:20]}"
        folder=(CODE_DIR/"backend"/"uploads").resolve();folder.mkdir(parents=True,exist_ok=True)
        path=(folder/f"{file_id}{suffix}").resolve();path.relative_to(folder);path.write_bytes(content)
        with SessionLocal() as db:
            if db.get(UploadedFile,file_id) is None:
                db.add(UploadedFile(file_id=file_id,filename=safe,safe_path=str(path),content_type=content_type or "application/octet-stream",size_bytes=len(content),sha256=digest));db.commit()
        return {"file_id":file_id,"filename":safe,"size_bytes":len(content),"sha256":digest,"processing":"stored_for_review"}
