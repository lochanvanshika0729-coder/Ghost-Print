from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CaseRequest(StrictRequest):
    case_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    deterministic_case: dict | None = None


class RetrievalRequest(StrictRequest):
    case_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    deterministic_case: dict | None = None
    query: str = Field(default="", max_length=1800)
    evidence_id: str = Field(default="", max_length=160)
    system_id: str = Field(default="", max_length=120)
    limit: int = Field(default=8, ge=1, le=20)


class AnalyzeEvidenceRequest(RetrievalRequest):
    query: str = Field(default="", max_length=1200)


class ExplainCaseRequest(CaseRequest):
    pass


class InvestigateRequest(CaseRequest):
    pass


class _ModelConfigCheck(StrictRequest):
    @model_validator(mode="after")
    def validate_reserved(self):
        return self
