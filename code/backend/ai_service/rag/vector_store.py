from __future__ import annotations

import json
import hashlib
import math
import sqlite3
from pathlib import Path
from typing import Protocol

from .ingestion import Document


class Embedder(Protocol):
    name: str
    def encode(self, texts: list[str]) -> list[list[float]]: ...


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str):
        from sentence_transformers import SentenceTransformer
        self.name = model_name
        self.model = SentenceTransformer(model_name, device="cpu", local_files_only=True, trust_remote_code=False)

    def encode(self, texts: list[str]) -> list[list[float]]:
        result = self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return result.tolist()


class OllamaEmbedder:
    def __init__(self, client, model_name: str):
        self.client = client
        self.name = f"ollama:{model_name}"

    def encode(self, texts: list[str]) -> list[list[float]]:
        return self.client.embed(texts)


class SQLiteVectorStore:
    """A small local cosine-search index; no cloud vector store or external service."""

    def __init__(self, path: Path, embedder: Embedder | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.embedder = embedder
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS vectors (document_id TEXT PRIMARY KEY, model TEXT NOT NULL, content_hash TEXT NOT NULL, text TEXT NOT NULL, metadata TEXT NOT NULL, vector TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_vectors_model_hash ON vectors(model, content_hash)")

    def _connect(self):
        return sqlite3.connect(self.path)

    @property
    def available(self) -> bool:
        return self.embedder is not None

    @property
    def model(self) -> str | None:
        return self.embedder.name if self.embedder else None

    def inspect_index(self, model: str, documents: list[Document]) -> dict[str, int]:
        """Compare persisted metadata with current documents without embedding or writes."""
        expected = {
            doc.document_id: str(doc.metadata.get("content_hash") or hashlib.sha256(doc.text.encode("utf-8")).hexdigest())
            for doc in documents
        }
        with self._connect() as db:
            indexed = dict(db.execute("SELECT document_id, content_hash FROM vectors WHERE model=?", (model,)))
        matching = sum(1 for document_id, digest in expected.items() if indexed.get(document_id) == digest)
        return {
            "expected_documents": len(expected),
            "indexed_documents": len(indexed),
            "matching_documents": matching,
            "missing_documents": sum(1 for document_id in expected if document_id not in indexed),
            "stale_documents": sum(1 for document_id, digest in indexed.items() if expected.get(document_id) != digest),
        }

    def add_documents(self, documents: list[Document]) -> int:
        if not self.embedder:
            return 0
        model = self.embedder.name
        current = {doc.document_id: (doc, str(doc.metadata.get("content_hash") or hashlib.sha256(doc.text.encode("utf-8")).hexdigest())) for doc in documents}
        with self._connect() as db:
            for document_id, in db.execute("SELECT document_id FROM vectors WHERE model=?", (model,)).fetchall():
                if document_id not in current:
                    db.execute("DELETE FROM vectors WHERE model=? AND document_id=?", (model, document_id))
            existing = {row[0]: row[1] for row in db.execute("SELECT document_id, content_hash FROM vectors WHERE model=?", (model,))}
            for document_id, (doc, content_hash) in current.items():
                if existing.get(document_id) == content_hash:
                    db.execute("UPDATE vectors SET text=?, metadata=? WHERE model=? AND document_id=?", (
                        doc.text, json.dumps(doc.metadata, ensure_ascii=False), model, document_id))
        pending = [(doc, content_hash) for doc, content_hash in current.values()
                   if existing.get(doc.document_id) != content_hash]
        inserted = 0
        for start in range(0, len(pending), 8):
            batch = pending[start:start + 8]
            vectors = self.embedder.encode([doc.text for doc, _ in batch])
            if len(vectors) != len(batch):
                raise ValueError("Embedding provider returned a different number of vectors than requested")
            with self._connect() as db:
                for (doc, content_hash), vector in zip(batch, vectors):
                    db.execute("INSERT OR REPLACE INTO vectors VALUES (?, ?, ?, ?, ?, ?)", (
                        doc.document_id, model, content_hash, doc.text,
                        json.dumps(doc.metadata, ensure_ascii=False), json.dumps(vector),
                    ))
                    inserted += 1
        return inserted

    def search(self, query: str, limit: int = 8) -> list[dict]:
        if not self.embedder or not query.strip():
            return []
        query_vector = self.embedder.encode([query])[0]
        qnorm = math.sqrt(sum(float(v) * float(v) for v in query_vector)) or 1.0
        scored = []
        with self._connect() as db:
            rows = db.execute("SELECT document_id, text, metadata, vector FROM vectors WHERE model=?", (self.embedder.name,)).fetchall()
        for document_id, text, metadata, encoded in rows:
            vector = json.loads(encoded)
            vnorm = math.sqrt(sum(float(v) * float(v) for v in vector)) or 1.0
            size = min(len(query_vector), len(vector))
            score = sum(float(query_vector[i]) * float(vector[i]) for i in range(size)) / (qnorm * vnorm)
            scored.append({"document_id": document_id, "text": text, "metadata": json.loads(metadata), "score": score})
        return sorted(scored, key=lambda item: (-item["score"], item["document_id"]))[:max(1, min(limit, 20))]
