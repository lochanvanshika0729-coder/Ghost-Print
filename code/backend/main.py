from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .db import CODE_DIR, DatasetFile, SessionLocal, init_db
from .engine import AuditEngine, MAX_FILE_BYTES
from .schemas import CaseResponse, DashboardResponse, HealthResponse, IdentityResponse
from .ai_service.schemas import AnalyzeEvidenceRequest, CaseRequest, ExplainCaseRequest, InvestigateRequest, RetrievalRequest
from .ai_service.services.audit_service import LocalAIService
from .ai_service.llm.ollama_client import OllamaError

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("ghostguard.api")
FRONTEND = CODE_DIR / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    engine = AuditEngine()
    app.state.audit_engine = engine
    app.state.local_ai = LocalAIService(deterministic_engine=engine)
    with SessionLocal() as db:
        for entry in engine.manifest:
            row = db.get(DatasetFile, entry["file_id"])
            values = {"file_path":entry["file_path"],"captured_at":entry["captured_at"],
                      "readable":int(entry["readable"]),"error":entry["error"]}
            if row is None:
                db.add(DatasetFile(file_id=entry["file_id"], **values))
            else:
                for key, value in values.items(): setattr(row, key, value)
        db.commit()
    yield


app = FastAPI(title="GHOST PRINT API", version="1.0.0", description="Evidence-first deletion audit API", lifespan=lifespan)
origins = [x.strip() for x in os.getenv("GHOSTGUARD_CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5173,http://127.0.0.1:5173").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type"])


@app.exception_handler(HTTPException)
async def api_http_error(request, exc: HTTPException):
    detail = exc.detail
    message = detail.get("error", str(detail)) if isinstance(detail, dict) else str(detail)
    return JSONResponse(status_code=exc.status_code, content={"error":message})


@app.exception_handler(RequestValidationError)
async def api_validation_error(request, exc: RequestValidationError):
    safe_errors = [{"location": error.get("loc", []), "message": error.get("msg", "Invalid value"), "type": error.get("type", "value_error")} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"error":"Invalid request parameters", "details":safe_errors})


def service() -> AuditEngine:
    engine = getattr(app.state, "audit_engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail={"error":"Audit service is still starting"})
    return engine


def local_ai() -> LocalAIService:
    current = getattr(app.state, "local_ai", None)
    if current is None:
        raise HTTPException(status_code=503, detail={"error":"Local AI service is still starting"})
    return current


def ai_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail={"error":str(exc).strip("'")})
    if isinstance(exc, OllamaError):
        return HTTPException(status_code=503, detail={"error":str(exc)})
    if isinstance(exc, ValueError):
        return HTTPException(status_code=502, detail={"error":"Local AI response could not be validated"})
    return HTTPException(status_code=500, detail={"error":"Local AI request failed"})


def public_case(case: dict) -> dict:
    return {key:case[key] for key in ("case_id","deletion_status","risk_level","request","steps","explanation")}


@app.get("/api/health", response_model=HealthResponse)
def health():
    current = service()
    return {"status":"ok","product":"GHOST PRINT","requests":len(current.requests),"evidence_files":len(current.evidence)}


@app.get("/ai/health")
def ai_health():
    return local_ai().health()


@app.post("/ai/retrieve-evidence")
def ai_retrieve(payload: RetrievalRequest):
    try:
        return local_ai().retrieve_evidence(case_id=payload.case_id, query=payload.query,
                                            evidence_id=payload.evidence_id, system_id=payload.system_id,
                                            limit=payload.limit)
    except Exception as exc:
        raise ai_error(exc) from None


@app.post("/ai/analyze-evidence")
def ai_analyze(payload: AnalyzeEvidenceRequest):
    try:
        local_ai().require_model()
        return local_ai().analyze_evidence(payload.case_id, evidence_id=payload.evidence_id, query=payload.query,
                                           deterministic_case=payload.deterministic_case)
    except Exception as exc:
        raise ai_error(exc) from None


@app.post("/ai/explain-case")
def ai_explain(payload: ExplainCaseRequest):
    try:
        local_ai().require_model()
        return local_ai().explain_case(payload.case_id, payload.deterministic_case)
    except Exception as exc:
        raise ai_error(exc) from None


@app.post("/ai/investigate")
def ai_investigate(payload: InvestigateRequest):
    try:
        local_ai().require_model()
        return local_ai().investigate(payload.case_id, payload.deterministic_case)
    except Exception as exc:
        raise ai_error(exc) from None


@app.get("/api/dashboard/summary", response_model=DashboardResponse)
def dashboard():
    return service().dashboard()


@app.get("/api/forensics/aggregate")
def forensics_aggregate():
    """Return the fields needed by cross-case charts without subject identifiers."""
    cases = service().cases()
    return {
        "total": len(cases),
        "items": [{
            "case_id": case["case_id"],
            "deletion_status": case["deletion_status"],
            "risk_level": case.get("risk_level", "UNKNOWN"),
            "request": {
                "requested_at": (case.get("request") or {}).get("requested_at", ""),
                "audit_at": (case.get("request") or {}).get("audit_at", ""),
            },
            "steps": [{key: step.get(key, "") for key in (
                "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
            )} for step in case.get("steps", [])],
        } for case in cases],
    }


@app.get("/api/datasets")
def datasets():
    return [service().dataset()]


@app.get("/api/datasets/official-challenge")
def dataset_detail():
    return service().dataset()


@app.post("/api/datasets/upload", status_code=201)
async def upload_dataset(file: UploadFile = File(...)):
    current = service()
    try:
        content = await file.read(MAX_FILE_BYTES + 1)
        result = current.store_upload(file.filename or "upload", content, file.content_type or "application/octet-stream")
        return result
    except ValueError as exc:
        raise HTTPException(status_code=413 if "limit" in str(exc).casefold() else 415, detail={"error":str(exc)}) from exc
    finally:
        await file.close()


@app.post("/api/investigations/run")
def run_investigations():
    cases = service().cases()
    return {"processed":len(cases),"results":len(cases)}


@app.get("/api/investigations")
def investigations(q: str = "", status: str = "", risk: str = "", offset: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=1000)):
    current = service()
    items = current.cases()
    if status:
        items = [x for x in items if x["deletion_status"] == status.upper()]
    if risk:
        items = [x for x in items if x["risk_level"] == risk.upper()]
    if q:
        needle = q.casefold()
        items = [x for x in items if needle in " ".join((x["case_id"],x["request"].get("email", ""),x["request"].get("request_text", ""))).casefold()]
    total = len(items)
    return {"total":total,"offset":offset,"limit":limit,"items":[public_case(x) for x in items[offset:offset+limit]]}


def get_case(case_id: str) -> dict:
    result = service().get(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error":"Case not found"})
    return result


def safe_findings(case: dict) -> list[dict]:
    return [{key:value for key,value in finding.items() if key!="_record"} for finding in case["findings"]]


@app.get("/api/investigations/{case_id}", response_model=CaseResponse)
def investigation_detail(case_id: str):
    return public_case(get_case(case_id))


@app.get("/api/investigations/{case_id}/identity", response_model=IdentityResponse)
def identity(case_id: str):
    return get_case(case_id)["identity"]


@app.get("/api/investigations/{case_id}/findings")
def findings(case_id: str):
    return safe_findings(get_case(case_id))


@app.post("/api/investigations/{case_id}/ai-explanation")
def ai_explanation(case_id: str):
    """Generate an advisory explanation only after an explicit UI request."""
    try:
        local_ai().require_model()
        return local_ai().explain_case(case_id, get_case(case_id))
    except Exception as exc:
        raise ai_error(exc) from None


@app.get("/api/investigations/{case_id}/evidence")
def evidence(case_id: str):
    result=get_case(case_id)
    refs={step.get("evidence_id") for step in result["steps"] if step.get("evidence_id")}
    return [item for item in service().manifest if item["file_id"] in refs]


@app.get("/api/investigations/{case_id}/timeline")
def timeline(case_id: str):
    result=get_case(case_id)
    return {"case_id":case_id,"request":result["request"],"steps":result["steps"]}


@app.get("/api/investigations/{case_id}/remediation")
def remediation(case_id: str):
    return [step for step in get_case(case_id)["steps"] if step["phase"]=="REMEDIATION"]


@app.get("/api/investigations/{case_id}/verification")
def verification(case_id: str):
    return [step for step in get_case(case_id)["steps"] if step["phase"]=="VERIFICATION"]


@app.get("/api/investigations/{case_id}/graph")
def lineage(case_id: str):
    case=get_case(case_id)
    # Recompute the graph so saved pre-lineage SQLite payloads cannot return the old
    # resource-id-only node shape or edges whose endpoints are not in the case graph.
    return service().analyze(case["request"])["graph"]


@app.get("/api/investigations/{case_id}/risks")
def case_risks(case_id: str):
    result=get_case(case_id)
    return {"case_id":case_id,"risk_level":result["risk_level"],"items":safe_findings(result)}


@app.get("/api/investigations/{case_id}/certificate")
def certificate(case_id: str):
    result=get_case(case_id)
    refs=sorted({step["evidence_id"] for step in result["steps"] if step.get("evidence_id")})
    return {"case_id":case_id,"evidence_refs":refs,"step_count":len(result["steps"]),"integrity_scope":"audit metadata and referenced evidence IDs only"}


@app.get("/api/risk-analysis")
def risk_analysis():
    return [{"case_id":c["case_id"],"risk_level":c["risk_level"],"items":safe_findings(c)} for c in service().cases() if c["findings"]]


@app.get("/api/reports/export")
def export_report():
    body=service().export_csv()
    return Response(content=body,media_type="text/csv; charset=utf-8",headers={"Content-Disposition":"attachment; filename=output.csv"})


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def frontend_index():
    index=FRONTEND/"index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail={"error":"Frontend files were not found"})
    return HTMLResponse(index.read_text(encoding="utf-8"))


if FRONTEND.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
