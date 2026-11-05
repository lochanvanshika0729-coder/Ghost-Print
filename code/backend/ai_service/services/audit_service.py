from __future__ import annotations

import time
from pathlib import Path

from ..config import Settings
from ..investigation.evidence_interpreter import EvidenceInterpreter
from ..llm.ollama_client import OllamaClient, OllamaError
from ..rag.ingestion import DatasetIngestor
from ..rag.retrieval import EvidenceRetriever
from ..rag.vector_store import OllamaEmbedder, SQLiteVectorStore, SentenceTransformerEmbedder


class LocalAIService:
    def __init__(self, dataset_dir: Path | None = None, deterministic_engine=None, settings: Settings | None = None):
        self.settings = settings or Settings.from_env()
        if dataset_dir:
            self.settings = Settings(**{**self.settings.__dict__, "dataset_dir": Path(dataset_dir).resolve()})
        self.engine = deterministic_engine
        self.ingestor = DatasetIngestor(self.settings.dataset_dir)
        self.ollama = OllamaClient(self.settings.ollama_url, self.settings.ollama_model,
                                   self.settings.request_timeout, self.settings.ollama_embedding_model)
        embedder = None
        self.embedding_error = ""
        try:
            if self.settings.embedding_provider == "sentence-transformers":
                embedder = SentenceTransformerEmbedder(self.settings.embedding_model)
            elif self.settings.embedding_provider == "ollama":
                embedder = OllamaEmbedder(self.ollama, self.settings.ollama_embedding_model)
            else:
                self.embedding_error = "Semantic embeddings are disabled by configuration."
        except Exception as exc:
            # Deliberately avoid returning exception text; it can include local paths.
            self.embedding_error = f"Local embedding model is unavailable ({type(exc).__name__})."
        self.vectors = SQLiteVectorStore(self.settings.embedding_cache, embedder)
        self.embedding_model = (embedder.name if embedder else
                                f"ollama:{self.settings.ollama_embedding_model}" if self.settings.embedding_provider == "ollama"
                                else self.settings.embedding_model)
        self.index_status = self.vectors.inspect_index(self.embedding_model, self.ingestor.documents)
        self.retriever = EvidenceRetriever(self.ingestor, self.vectors)
        self.interpreter = EvidenceInterpreter(self.retriever, self.ollama, self.ingestor.rules)
        self._index_error = ""

    def health(self) -> dict:
        ollama = self.ollama.health()
        if self.settings.embedding_provider == "ollama":
            embedding_base = self.settings.ollama_embedding_model.split(":", 1)[0]
            embedding_available = ollama["available"] and any(
                name == self.settings.ollama_embedding_model or name == f"{embedding_base}:latest"
                for name in ollama["installed_models"])
            if not embedding_available and not self.embedding_error:
                self.embedding_error = "Configured Ollama embedding model is unavailable."
        else:
            embedding_available = self.vectors.available
        index_ready = self.index_status["matching_documents"] > 0
        index_complete = (self.index_status["expected_documents"] > 0 and
                          self.index_status["matching_documents"] == self.index_status["expected_documents"])
        return {"status": "ok", "provider": "Ollama (local)", "model": self.settings.ollama_model,
                "ollama_available": ollama["available"], "model_installed": ollama["model_installed"],
                "installed_models": ollama["installed_models"], "ollama_message": ollama.get("message", ""),
                "dataset_documents": len(self.ingestor.documents), "manifest_entries": len(self.ingestor.manifest),
                "embedding_available": embedding_available,
                "index_ready": index_ready,
                "index_complete": index_complete,
                "index_status": "READY" if index_complete else "PARTIAL" if index_ready else "EMPTY",
                "index_model": self.embedding_model,
                **self.index_status,
                "semantic_retrieval_available": embedding_available and index_ready,
                "embedding_provider": self.settings.embedding_provider,
                "embedding_model": self.embedding_model,
                "embedding_message": self.embedding_error or self._index_error,
                "vector_index": "SQLite cosine search" if embedding_available and index_ready else "Unavailable; exact structured retrieval remains enabled",
                "automatic_reindex": False}

    def _ensure_index(self) -> None:
        # Reuse the persisted index. Request handlers never embed the full corpus;
        # missing/stale vectors are reported through health and exact retrieval stays
        # available for documents without a matching vector.
        return

    def retrieve_evidence(self, *, case_id: str, query: str = "", evidence_id: str = "", system_id: str = "", limit: int = 8) -> dict:
        self._ensure_index()
        return self.retriever.retrieve(case_id=case_id, query=query, evidence_id=evidence_id,
                                       system_id=system_id, limit=limit)

    def deterministic_case(self, case_id: str, supplied: dict | None = None) -> dict:
        if supplied is not None:
            if supplied.get("case_id") != case_id or supplied.get("deletion_status") not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
                raise ValueError("Invalid deterministic audit result")
            if not isinstance(supplied.get("steps"), list):
                raise ValueError("Invalid deterministic audit result")
            return supplied
        if not self.engine:
            raise RuntimeError("Deterministic audit engine is unavailable")
        result = self.engine.get(case_id)
        if result is None:
            raise KeyError("Case not found")
        return result

    def analyze_evidence(self, case_id: str, *, evidence_id: str = "", query: str = "", deterministic_case: dict | None = None) -> dict:
        self._ensure_index()
        case = self.deterministic_case(case_id, deterministic_case)
        started = time.perf_counter()
        result = self.interpreter.analyze(case_id, evidence_id=evidence_id, query=query, deterministic_case=case)
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return result

    def explain_case(self, case_id: str, deterministic_case: dict | None = None) -> dict:
        self._ensure_index()
        case = self.deterministic_case(case_id, deterministic_case)
        request = self.ingestor.requests_by_id.get(case_id, {})
        return self.interpreter.explain(case_id, case, request)

    def investigate(self, case_id: str, deterministic_case: dict | None = None) -> dict:
        self._ensure_index()
        case = self.deterministic_case(case_id, deterministic_case)
        analysis = self.interpreter.analyze(case_id, deterministic_case=case)
        return {"case_id": case_id, "deletion_status": case["deletion_status"],
                "deterministic_steps": case["steps"], "ai_findings": analysis["findings"],
                "rejected_ai_findings": analysis["rejected_findings"], "model": analysis.get("model"),
                "message": analysis.get("message", ""),
                "decision_authority": "Deterministic audit engine; AI interpretation does not change status or steps."}

    def require_model(self) -> None:
        health = self.ollama.health()
        if not health["available"]:
            raise OllamaError(health.get("message") or "Ollama is unavailable.")
        if not health["model_installed"]:
            raise OllamaError(f"Configured model is not installed. Run: ollama pull {self.settings.ollama_model}")
