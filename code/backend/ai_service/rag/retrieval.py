from __future__ import annotations

import re
from typing import Any

from .ingestion import DatasetIngestor, Document, _system_for_resource, _time, normalize
from .vector_store import SQLiteVectorStore


def _contains_exact(text: str, identifier: str) -> bool:
    if not identifier:
        return False
    return re.search(r"(?<![\w@.+-])" + re.escape(identifier) + r"(?![\w@.+-])", text, re.IGNORECASE) is not None


class EvidenceRetriever:
    def __init__(self, ingestor: DatasetIngestor, vectors: SQLiteVectorStore):
        self.ingestor = ingestor
        self.vectors = vectors
        self._documents = ingestor.documents
        self._docs_by_evidence: dict[str, list[Document]] = {}
        for document in self._documents:
            for evidence_id in document.metadata.get("evidence_ids", [document.metadata.get("evidence_id")]):
                if not evidence_id:
                    continue
                self._docs_by_evidence.setdefault(evidence_id, []).append(document)

    def retrieve(self, *, case_id: str, query: str = "", evidence_id: str = "", system_id: str = "", limit: int = 8) -> dict[str, Any]:
        request, identity, aliases, history = self.ingestor.resolve_case(case_id)
        if not request:
            raise KeyError("Case not found")
        cutoff = _time(request.get("audit_at"))
        exact: list[dict[str, Any]] = []
        seen: set[str] = set()

        def include(document: Document, reason: str, identity_linked: bool = False):
            key = document.document_id
            if key in seen:
                return
            metadata = document.metadata
            if metadata.get("kind") == "evidence":
                sources = metadata.get("evidence_sources", [])
                if not sources:
                    sources = [{"evidence_id": metadata.get("evidence_id"), "captured_at": metadata.get("captured_at", ""),
                                "source_system": metadata.get("source_system", "")}]
                resource_system = _system_for_resource(metadata.get("resource_id", ""))
                sources = [{**source, "source_system": source.get("source_system") or metadata.get("source_system") or resource_system}
                           for source in sources]
                sources = [source for source in sources
                           if (not evidence_id or source.get("evidence_id") == evidence_id)
                           and (not system_id or normalize(source.get("source_system")) == normalize(system_id))
                           and (not cutoff or (_time(source.get("captured_at")) is not None and _time(source.get("captured_at")) <= cutoff))]
                if not sources:
                    return
                metadata = {**metadata, "evidence_sources": sources,
                            "evidence_ids": sorted({source.get("evidence_id") for source in sources if source.get("evidence_id")})}
                metadata["evidence_id"] = metadata["evidence_ids"][0] if metadata["evidence_ids"] else ""
                metadata["captured_at"] = min((source.get("captured_at", "") for source in sources if source.get("captured_at")), default="")
                systems = {source.get("source_system", "") for source in sources if source.get("source_system")}
                metadata["source_system"] = next(iter(systems)) if len(systems) == 1 else metadata.get("source_system", "")
            seen.add(key)
            exact.append({"document_id": key, "text": document.text[:5000], "metadata": metadata,
                          "match": reason, "identity_linked": identity_linked, "score": 1.0})

        if evidence_id:
            if evidence_id not in self.ingestor.manifest_by_id:
                raise KeyError("Evidence ID not found")
            for document in self._docs_by_evidence.get(evidence_id, []):
                linked = any(_contains_exact(document.text, alias) for alias in aliases)
                # An evidence-ID lookup is still scoped to the resolved subject. A
                # file identifier is not proof that every row in that file belongs
                # to this case.
                if linked:
                    include(document, "evidence_id", True)
        else:
            for document in self._documents:
                metadata = document.metadata
                if metadata.get("kind") != "evidence":
                    if metadata.get("case_id") == case_id:
                        include(document, "case_id", True)
                    elif identity and metadata.get("user_id") == identity.get("user_id"):
                        include(document, "user_id", True)
                    elif metadata.get("kind") == "deletion_policy":
                        include(document, "policy", False)
                    elif metadata.get("kind") == "system_activity" and any(_contains_exact(document.text, alias) for alias in aliases):
                        include(document, "exact_identifier", True)
                    continue
                metadata_system = normalize(metadata.get("source_system"))
                if system_id and metadata_system != normalize(system_id):
                    continue
                if aliases and any(_contains_exact(document.text, alias) for alias in aliases):
                    include(document, "exact_identifier", True)

        structured_count = len(exact)
        semantic = []
        semantic_error = ""
        semantic_query = (query or f"{request.get('request_text', '')} {request.get('reported_status', '')}").strip()[:1800]
        if self.vectors.available and semantic_query:
            try:
                results = self.vectors.search(semantic_query, limit=max(limit * 3, 12))
            except Exception as exc:
                # A dead or unavailable embedder must not take exact retrieval down.
                semantic_error = type(exc).__name__
                results = []
            for result in results:
                metadata = result["metadata"]
                if metadata.get("kind") != "evidence" or result["document_id"] in seen:
                    continue
                sources = metadata.get("evidence_sources", [])
                if not sources:
                    sources = [{"evidence_id": metadata.get("evidence_id", ""),
                                "captured_at": metadata.get("captured_at", ""),
                                "source_system": metadata.get("source_system", "")}]
                resource_system = _system_for_resource(metadata.get("resource_id", ""))
                sources = [{**source, "source_system": source.get("source_system") or metadata.get("source_system") or resource_system}
                           for source in sources]
                valid_sources = [source for source in sources
                                 if (not evidence_id or source.get("evidence_id") == evidence_id)
                                 and (not system_id or normalize(source.get("source_system")) == normalize(system_id))
                                 and (not cutoff or (_time(source.get("captured_at")) is not None and _time(source.get("captured_at")) <= cutoff))]
                if not valid_sources:
                    continue
                # Semantic similarity is only a ranking signal. It never resolves
                # identity or authorizes a cross-user evidence excerpt.
                linked = any(_contains_exact(result["text"], alias) for alias in aliases)
                if not linked:
                    continue
                metadata = {**metadata, "evidence_sources": valid_sources,
                            "evidence_ids": sorted({source.get("evidence_id") for source in valid_sources if source.get("evidence_id")})}
                metadata["evidence_id"] = metadata["evidence_ids"][0] if metadata["evidence_ids"] else ""
                metadata["captured_at"] = min((source.get("captured_at", "") for source in valid_sources if source.get("captured_at")), default="")
                systems = {source.get("source_system", "") for source in valid_sources if source.get("source_system")}
                metadata["source_system"] = next(iter(systems)) if len(systems) == 1 else metadata.get("source_system", "")
                semantic.append({**result, "metadata": metadata, "match": "semantic", "identity_linked": True})
                seen.add(result["document_id"])
                if len(semantic) >= limit:
                    break

        exact.sort(key=lambda item: (item["metadata"].get("kind") != "evidence", item["metadata"].get("evidence_id", ""), item["document_id"]))
        return {
            "case_id": case_id,
            "audit_cutoff": request.get("audit_at", ""),
            "identity_resolution": "RESOLVED" if identity else "UNRESOLVED_OR_AMBIGUOUS",
            "structured_matches": structured_count,
            "semantic_available": self.vectors.available and not semantic_error,
            "semantic_error": semantic_error,
            "semantic_model": self.vectors.model,
            "items": (exact[:max(1, min(limit, 20))] + semantic)[:20],
        }
