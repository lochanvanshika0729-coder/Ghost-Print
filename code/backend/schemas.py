from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    status: Literal["ok"]
    product: str
    requests: int
    evidence_files: int


class StepResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step_no: int
    phase: Literal["FINDING", "REMEDIATION", "VERIFICATION"]
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


class IdentityResponse(BaseModel):
    user_id: str | None = None
    current_email: str | None = None
    historical_emails: list[str] = Field(default_factory=list)
    historical_identifiers: dict[str, list[str]] = Field(default_factory=dict)
    known_identifiers: list[str] = Field(default_factory=list)
    resolution_status: str = "UNRESOLVED"
    evidence_ids: list[str] = Field(default_factory=list)


class CaseResponse(BaseModel):
    case_id: str
    deletion_status: Literal["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]
    risk_level: str = "UNKNOWN"
    request: dict
    steps: list[StepResponse]
    explanation: str


class DashboardResponse(BaseModel):
    total_requests: int
    completed: int
    incomplete: int
    not_applicable: int
    high_risk_cases: int
    active_flows: int
    restore_risks: int
    by_system: dict[str, int]
    risk_distribution: dict[str, int]
    recent: list[CaseResponse]
