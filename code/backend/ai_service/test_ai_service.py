from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from .config import Settings, _local_url
from .investigation.evidence_interpreter import EvidenceInterpreter
from .schemas import AnalyzeEvidenceRequest, ExplainCaseRequest, InvestigateRequest
from .rag.ingestion import DatasetIngestor, _read_sql, chunk_text
from .rag.retrieval import EvidenceRetriever
from .rag.vector_store import SQLiteVectorStore
from .services.audit_service import LocalAIService


class FakeOllama:
    model = "fake-local-model"


class GroundedAINodeTests(unittest.TestCase):
    def test_remote_model_endpoints_are_rejected(self):
        self.assertEqual(_local_url("http://127.0.0.1:11434", "ollama"), "http://127.0.0.1:11434")
        with self.assertRaises(ValueError):
            _local_url("https://example.com", "ollama")

    def test_local_ai_service_health_does_not_require_ollama(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._small_dataset(root)
            settings = Settings(
                ollama_url="http://127.0.0.1:11435", ollama_model="missing-model",
                ollama_embedding_model="missing-embedder", embedding_model="unused",
                embedding_provider="ollama", embedding_cache=root / "index.sqlite3",
                dataset_dir=root, request_timeout=2, max_evidence_chars=12000, max_chunks=8,
            )
            health = LocalAIService(settings=settings).health()
            self.assertEqual(health["status"], "ok")
            self.assertFalse(health["ollama_available"])
            self.assertFalse(health["model_installed"])
            self.assertFalse(health["embedding_available"])

    def test_node_deterministic_case_is_allowed_on_all_ai_request_schemas(self):
        node_case = {"case_id":"case_1", "deletion_status":"INCOMPLETE", "steps":[]}
        self.assertEqual(AnalyzeEvidenceRequest(case_id="case_1", deterministic_case=node_case).deterministic_case, node_case)
        self.assertEqual(ExplainCaseRequest(case_id="case_1", deterministic_case=node_case).deterministic_case, node_case)
        self.assertEqual(InvestigateRequest(case_id="case_1", deterministic_case=node_case).deterministic_case, node_case)

    def test_chunking_has_overlap_and_no_empty_chunks(self):
        text = "A sentence. " * 100
        chunks = chunk_text(text, size=100, overlap=20)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(chunks))
        self.assertIn(chunks[0][-20:], chunks[1])

    def _small_dataset(self, root: Path):
        (root / "evidence" / "records").mkdir(parents=True)
        fixtures = {
            "deletion_requests.csv": [{"case_id":"case_1", "email":"old@example.invalid", "requested_at":"2026-01-01T00:00:00Z", "audit_at":"2026-02-01T00:00:00Z", "request_text":"Delete my account"}],
            "user_identities.csv": [{"user_id":"user_1", "email":"new@example.invalid", "name":"Fictional Example", "updated_at":"2026-01-20T00:00:00Z"}],
            "user_audit_log.csv": [{"audit_id":"audit_1", "user_id":"user_1", "field_name":"email", "old_value":"old@example.invalid", "new_value":"new@example.invalid", "event_time":"2026-01-20T00:00:00Z"}],
            "system_activity.csv": [{"activity_id":"activity_1", "user_id":"user_1", "event_type":"delete", "event_time":"2026-01-25T00:00:00Z"}],
            "deletion_rules.csv": [{"rule_id":"rule_1", "data_category":"SUPPORT_MESSAGE", "required_action":"DELETE"}],
            "evidence_files.csv": [{"file_id":"evidence_1", "file_path":"evidence/records/one.json", "origin":"support", "captured_at":"2026-01-30T00:00:00Z"},
                                   {"file_id":"evidence_late", "file_path":"evidence/records/late.json", "origin":"support", "captured_at":"2026-03-01T00:00:00Z"},
                                   {"file_id":"evidence_other", "file_path":"evidence/records/other.json", "origin":"support", "captured_at":"2026-01-30T00:00:00Z"}],
        }
        for name, rows in fixtures.items():
            with (root / name).open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader(); writer.writerows(rows)
        (root / "evidence" / "records" / "one.json").write_text(json.dumps({"resource_id":"support_1", "system_id":"support_service", "data_category":"SUPPORT_MESSAGE", "email":"old@example.invalid", "record_state":"PRESENT"}), encoding="utf-8")
        (root / "evidence" / "records" / "late.json").write_text(json.dumps({"resource_id":"support_2", "system_id":"support_service", "email":"old@example.invalid"}), encoding="utf-8")
        (root / "evidence" / "records" / "other.json").write_text(json.dumps({"resource_id":"support_3", "system_id":"support_service", "data_category":"SUPPORT_MESSAGE", "email":"different@example.invalid", "record_state":"PRESENT"}), encoding="utf-8")

    def test_exact_historical_identity_matches_evidence_and_honors_cutoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._small_dataset(root)
            ingestor = DatasetIngestor(root)
            retriever = EvidenceRetriever(ingestor, SQLiteVectorStore(root / "index.sqlite3"))
            result = retriever.retrieve(case_id="case_1", query="remaining support message")
            ids = {item["metadata"].get("evidence_id") for item in result["items"]}
            self.assertIn("evidence_1", ids)
            self.assertNotIn("evidence_late", ids)
            matched = [item for item in result["items"] if item["metadata"].get("evidence_id") == "evidence_1"]
            self.assertTrue(matched[0]["identity_linked"])
            self.assertFalse(result["semantic_available"])
            filtered = retriever.retrieve(case_id="case_1", evidence_id="evidence_1", system_id="support_service")
            self.assertTrue(all("evidence_1" in item["metadata"].get("evidence_ids", []) for item in filtered["items"] if item["metadata"].get("kind") == "evidence"))
            self.assertTrue(any(item["metadata"].get("evidence_id") == "evidence_1" for item in filtered["items"]))
            unrelated = retriever.retrieve(case_id="case_1", evidence_id="evidence_other")
            self.assertFalse(any(item["metadata"].get("kind") == "evidence" for item in unrelated["items"]))

    def test_semantic_candidates_without_exact_identity_link_are_dropped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._small_dataset(root)
            ingestor = DatasetIngestor(root)
            class SemanticVectors:
                available = True
                model = "test"
                def search(self, query, limit=8):
                    doc = next(item for item in ingestor.documents if item.metadata.get("evidence_id") == "evidence_other")
                    return [{"document_id":doc.document_id,"text":doc.text,"metadata":doc.metadata,"score":0.9}]
            retriever = EvidenceRetriever(ingestor, SemanticVectors())
            result = retriever.retrieve(case_id="case_1", query="support message")
            self.assertFalse(any(item["metadata"].get("evidence_id") == "evidence_other" for item in result["items"]))

    def test_semantic_failure_falls_back_to_exact_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._small_dataset(root)
            ingestor = DatasetIngestor(root)
            class BrokenVectors:
                available = True
                model = "offline"
                def search(self, *_args, **_kwargs):
                    raise RuntimeError("embedding service unavailable")
            result = EvidenceRetriever(ingestor, BrokenVectors()).retrieve(case_id="case_1", query="support message")
            self.assertFalse(result["semantic_available"])
            self.assertEqual(result["semantic_error"], "RuntimeError")
            self.assertTrue(any(item["metadata"].get("evidence_id") == "evidence_1" for item in result["items"]))

    def test_sql_ingestion_accepts_snapshot_indexes_without_allowing_attach(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._small_dataset(root)
            sql = root / "evidence" / "records" / "snapshot.sql"
            sql.write_text("PRAGMA foreign_keys=ON; CREATE TABLE records(resource_id TEXT PRIMARY KEY, email TEXT, payload TEXT CHECK(json_valid(payload))); CREATE INDEX idx_email ON records(email); INSERT INTO records VALUES('support_9','old@example.invalid','{}');", encoding="utf-8")
            (root / "evidence_files.csv").write_text(
                "file_id,file_path,origin,captured_at\nevidence_sql,evidence/records/snapshot.sql,db,2026-01-30T00:00:00Z\n",
                encoding="utf-8")
            ingestor = DatasetIngestor(root)
            rows = ingestor.evidence_records("evidence_sql")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["email"], "old@example.invalid")
            unsafe = root / "evidence" / "records" / "unsafe.sql"
            unsafe.write_text("ATTACH DATABASE '/tmp/not-allowed.db' AS external;", encoding="utf-8")
            with self.assertRaises(Exception):
                _read_sql(unsafe)

    def test_supplied_node_audit_is_authoritative_for_ai_investigation(self):
        class PythonEngine:
            def get(self, _case_id):
                return {"case_id":"case_1", "deletion_status":"COMPLETE", "steps":[]}
        class Interpreter:
            def analyze(self, *_args, **_kwargs):
                return {"findings":[{"evidence_id":"evidence_1"}], "rejected_findings":1}
        service = object.__new__(LocalAIService)
        service.engine = PythonEngine()
        service.interpreter = Interpreter()
        service._ensure_index = lambda: None
        node_case = {"case_id":"case_1", "deletion_status":"INCOMPLETE", "steps":[{"phase":"FINDING","evidence_id":"evidence_1"}]}
        result = service.investigate("case_1", node_case)
        self.assertEqual(result["deletion_status"], "INCOMPLETE")
        self.assertEqual(result["deterministic_steps"], node_case["steps"])
        self.assertEqual(result["ai_findings"], [{"evidence_id":"evidence_1"}])
        self.assertEqual(service.deterministic_case("case_1")["deletion_status"], "COMPLETE")

    def test_custom_residual_secondary_record_finding_is_grounded(self):
        accepted = self._validate_custom("RESIDUAL_RECORD", "SUPPORT_MESSAGE", "DELETE", "evidence_valid")
        self.assertEqual(len(accepted), 1)

    def test_custom_active_sync_risk_has_no_invented_policy_rule(self):
        accepted = self._validate_custom("ACTIVE_DATA_FLOW", "", "", "evidence_valid", applicable_rule=None)
        self.assertEqual(len(accepted), 1)
        self.assertIsNone(accepted[0]["applicable_rule"])

    def test_custom_retained_record_uses_the_supplied_retain_rule(self):
        accepted = self._validate_custom("POLICY_RETENTION", "SECURITY_AUDIT_LOG", "RETAIN", "evidence_valid")
        self.assertEqual(accepted[0]["applicable_rule"]["required_action"], "RETAIN")

    def test_interpreter_prompt_includes_only_matching_policy_rules(self):
        linked = [{"metadata":{"data_category":"SUPPORT_MESSAGE"},"text":"linked support evidence"}]
        facts = json.loads(EvidenceInterpreter._prompt_facts(linked, None, {
            "SUPPORT_MESSAGE":{"rule_id":"r1","data_category":"SUPPORT_MESSAGE","required_action":"DELETE"},
            "SECURITY_AUDIT_LOG":{"rule_id":"r2","data_category":"SECURITY_AUDIT_LOG","required_action":"RETAIN"},
        }))
        self.assertEqual([rule["data_category"] for rule in facts["deletion_policy_rules"]], ["SUPPORT_MESSAGE"])

    def test_hallucinated_evidence_reference_is_rejected(self):
        accepted = self._validate_custom("RESIDUAL_RECORD", "SUPPORT_MESSAGE", "DELETE", "evidence_invented")
        self.assertEqual(accepted, [])

    def test_unrecognized_source_system_and_missing_policy_rule_are_rejected(self):
        linked = [{"metadata":{"evidence_id":"evidence_valid", "evidence_ids":["evidence_valid"],
                              "source_system":"support_service", "data_category":"SUPPORT_MESSAGE"},
                   "text":"Exact-identifier-linked test record."}]
        interpreter = EvidenceInterpreter(None, FakeOllama(), [
            {"data_category":"SUPPORT_MESSAGE", "required_action":"DELETE"},
        ])
        base = {"case_id":"case_test", "finding_category":"RESIDUAL_RECORD",
                "detected_issue":"A record is present.", "explanation":"Evidence supports the classification.",
                "confidence":0.8, "applicable_rule":{"data_category":"SUPPORT_MESSAGE","required_action":"DELETE"}}
        wrong_system, _ = interpreter.validate_findings("case_test", {"case_id":"case_test", "findings":[{
            **base,"evidence_id":"evidence_valid","source_system":"invented_service"}]}, linked)
        no_rule, _ = interpreter.validate_findings("case_test", {"case_id":"case_test", "findings":[{
            **base,"evidence_id":"evidence_valid","source_system":"support_service","applicable_rule":None}]}, linked)
        self.assertEqual(wrong_system, [])
        self.assertEqual(no_rule, [])

    def _validate_custom(self, category, rule_category, action, evidence_id, applicable_rule="SET"):
        linked = [{"metadata":{"evidence_id":"evidence_valid", "evidence_ids":["evidence_valid"],
                              "source_system":"support_service", "data_category":rule_category},
                   "text":"Exact-identifier-linked test record."}]
        interpreter = EvidenceInterpreter(None, FakeOllama(), [
            {"data_category":"SUPPORT_MESSAGE", "required_action":"DELETE"},
            {"data_category":"SECURITY_AUDIT_LOG", "required_action":"RETAIN"},
        ])
        rule = None if applicable_rule is None else {"data_category":rule_category, "required_action":action}
        response = {"case_id":"case_test", "findings":[{
            "evidence_id":evidence_id, "source_system":"support_service", "finding_category":category,
            "detected_issue":"A linked record needs policy review.", "explanation":"The exact matched evidence supports this advisory.",
            "confidence":0.8, "applicable_rule":rule,
        }]}
        validated, _rejected = interpreter.validate_findings("case_test", response, linked)
        return validated


if __name__ == "__main__":
    unittest.main()
