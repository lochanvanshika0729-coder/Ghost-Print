# GHOST PRINT

A responsive, evidence-first deletion audit workspace for the HackerRank Orchestrate dataset. The local UI is served by a small Node.js service and reads participant-facing files from `dataset/`. No external systems are modified and proposed remediation is never shown as completed work.

## Run locally

Requires Node.js 20 or later. No package installation is required.

```bash
npm run dev
```

Open the URL printed by the server (normally <http://localhost:8000>) for the public Ghost Print landing page. Choose **Enter workspace** or open <http://localhost:8000/dashboard> to use the existing application. If that port is already occupied, the server automatically tries the next port and prints the new URL. You can also choose a port with `PORT=8080 npm run dev`. The workspace includes Overview, Deletion Audits, individual audit details, Data Lineage, Risk Analysis, Forensics, Certificates, Reports, and Settings. Forensics aggregates evidence-backed case/resource findings across the loaded cases and compares selected audits. Search, filtering, sorting, pagination, evidence expanders, local integrity hashing, CSV downloads, and print-to-PDF are available. The project does not configure sign-in or registration; the landing page links directly to the workspace.

## Run the FastAPI backend

Python 3.12 is the tested setup for the pinned backend dependencies. From the repository root, create and activate an isolated virtual environment, then install the backend dependencies:

```powershell
python3.12 -m venv /tmp/ghostguard-venv
source /tmp/ghostguard-venv/bin/activate
python -m pip install -r code/requirements.txt
RAG_EMBEDDING_PROVIDER=ollama python -m uvicorn backend.main:app --app-dir code --host 127.0.0.1 --port 8001
```

The Node app remains on port 8000. FastAPI binds to loopback on port 8001 and supplies the local AI/RAG service consumed by Node. API documentation is available at <http://127.0.0.1:8001/docs>. The service stores parsed investigation results in `code/backend/ghostguard.sqlite3`; uploads are not used to change a case result.

Run FastAPI and Node in separate terminals. FastAPI uses port 8001; Node uses port 8000 and proxies AI requests to FastAPI. `npm run dev` runs the repository's frontend build hook before starting Node; to run only the existing application server without that build step, use `node code/server.js`. The Node app remains available when the optional AI service is stopped, and AI routes return a local-service error instead of taking down Node.

## Local LLM and RAG

The **Explain with AI** action and the added investigation endpoints use Ollama on the same machine. No AI API key, external model endpoint, or cloud provider is used. Copy the local defaults and install Ollama using its official installer for your operating system:

```bash
cp code/.env.example code/.env
ollama pull qwen3:1.7b
```

This workspace has about 7.8 GiB system memory available to the container and no detected NVIDIA GPU. Qwen3 1.7B Q4 is the conservative default; Ollama lists the model at about 1.4 GB. A smaller fallback is `qwen3:0.6b`; `qwen3:4b` is a higher-memory option. Change `OLLAMA_MODEL` in `code/.env` and pull that exact tag before use. [Ollama Qwen3 model tags](https://ollama.com/library/qwen3/tags)

The configured chat model is `qwen3:1.7b`. Ollama must run on the same machine at `127.0.0.1:11434`; the implementation accepts loopback Ollama URLs only. Pull both the chat and embedding models before starting semantic RAG:

```bash
ollama pull qwen3:1.7b
ollama pull nomic-embed-text
```

Set `RAG_EMBEDDING_PROVIDER=ollama` for the API process. Sentence Transformers remains an optional alternative from `code/requirements-ai.txt`; its model must already be cached because runtime loading is local-only. The SQLite vector store is `code/backend/ai_rag.sqlite3` and is ignored by Git. Existing vectors are reused; requests do not automatically re-embed missing or stale documents. `/ai/health` reports embedding availability separately from index readiness and coverage. Exact retrieval continues when semantic search is unavailable or the index is partial.

The dataset is read from `dataset/`; the RAG ingestor intentionally excludes sample answers and generated output. It indexes request, identity, identity-history, activity, policy, and manifest-linked evidence files. Supported evidence includes text/log, CSV-like text, JSON, and SQLite-compatible SQL. PDF text extraction needs the standard backend dependency; image OCR additionally needs Tesseract installed. Duplicate evidence chunks retain all source evidence IDs and filenames.

Structured exact matching of the current and historical identifiers, case IDs, evidence IDs, activity records, and policy categories runs before semantic search. Semantic similarity never establishes subject identity. The LLM only interprets exact identity-linked evidence and cannot set deletion status, change steps, invent evidence IDs, or claim remediation was executed. Every returned AI finding must cite an in-cutoff evidence ID, a source system found in the evidence or deterministic case, and a policy action present in `deletion_rules.csv`. Invalid references are discarded. The deterministic Node audit result remains the authority for `COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE`.

The Python service exposes `GET /ai/health`, `POST /ai/retrieve-evidence`, `POST /ai/analyze-evidence`, `POST /ai/explain-case`, and `POST /ai/investigate`. Node proxies the same routes under `/api/ai/*`; the existing `POST /api/investigations/{case_id}/ai-explanation` route remains available for the current UI. The service binds to `127.0.0.1`; Node rejects non-loopback browser origins for local AI routes. Evidence text and model prompts are not written to logs. Retrieved evidence is treated as untrusted input and prompt-injection instructions inside it are ignored.

The service reports Ollama and embedding model availability separately from vector-index readiness. AI investigation is advisory: the Node audit result is passed to FastAPI and returned unchanged alongside AI findings. AI findings are checked against retrieved, identity-linked evidence IDs, source systems, and supplied policy rules; they cannot set the deletion status or remediation steps. Live model output is not a substitute for review of the underlying evidence. Keep Ollama, the service, and its local index on a machine authorized to hold this dataset.

To set the required challenge output at repository root:

```bash
node code/server.js --export
```

`npm run dev` is configured by the repository-root `package.json` and works from `/workspaces/Ghost-Print`; no `npm install` step is needed.

## FastAPI integration

The browser service adapter is `frontend/api.js`; illustrative display-only examples live separately in `frontend/demo-data.js`. It expects the following routes, implemented by `backend/main.py`. Set `window.GHOSTGUARD_API_BASE` before `/api.js` loads to point the client to another origin.

- `GET /api/health`
- `GET /api/dashboard/summary`
- `GET /api/forensics/aggregate` (case/resource risk counts and audit dates without subject identifiers)
- `GET /api/investigations?q=&status=&offset=&limit=`
- `GET /api/investigations/{case_id}`
- `GET /api/investigations/{case_id}/identity|findings|remediation|verification|graph|risks|certificate`
- `GET /api/investigations/{case_id}/evidence|timeline`
- `GET /api/investigations/{case_id}/graph` (unique resource observations and only explicitly evidenced resource-to-resource relationships)
- `POST /api/investigations/{case_id}/ai-explanation` (local Ollama explanation, user-triggered)
- `GET /api/ai/health`, `POST /api/ai/retrieve-evidence`, `POST /api/ai/analyze-evidence`, `POST /api/ai/explain-case`, and `POST /api/ai/investigate` (local FastAPI proxy endpoints)
- `GET /api/datasets/official-challenge`
- `POST /api/datasets/upload` (validated, quarantined upload)
- `GET /api/risk-analysis`
- `GET /api/reports/export`

The UI consumes service responses through `GhostguardAPI`; mock records are not coupled to components. The backend returns evidence-linked observation nodes and only emits a lineage edge when a source record explicitly names both endpoints and a relationship. The case risk band is a disclosed prioritization heuristic, not a legal privacy guarantee.

### Data Lineage

The browser renders the backend graph with a dependency-free SVG view. The case selector loads the full investigation list; each selected case requests its own graph. Resource nodes are deduplicated by the stable `(system_id, resource_id)` pair, retain all associated evidence references, and keep presence state separate from verification status. Nodes can be selected and dragged, the canvas can be panned or wheel-zoomed, and **Reset / fit** fits the current case graph. The API accepts only explicit relationship records with both resource endpoints and a relationship type, and omits edges whose endpoints are absent, ambiguous, or self-referencing. If the evidence does not describe such a relationship, the UI displays the resources independently and says no verified resource-to-resource relationships were found. It does not infer links from matching system names or activity alone.

The repository’s participant evidence currently has resource observations but no explicit resource-to-resource endpoint fields for case `case_34`; its graph therefore correctly has one unique support resource and no edges. The optional FastAPI backend uses the same response shape for nodes and supported edges. Its graph is built from the evidence-backed findings and verification steps returned by its audit engine.

Evidence matching, policy coverage, OCR support, and temporal reconstruction have known limitations; see `evaluation/evaluation_report.md`. Structural output validation does not establish prediction accuracy.

Run the Node suite with `npm test`. Run dependency-free AI/RAG unit checks from `code/` using `python -m unittest backend.ai_service.test_ai_service -v`. After installing backend dependencies, run all Python checks with `python -m pytest backend/test_engine.py backend/ai_service/test_ai_service.py`.

## Evidence and integrity boundaries

- Audit state is evaluated at the request's `audit_at` cutoff.
- Missing or unsupported evidence is not proof that data is gone.
- Findings cite evidence references from the generated audit steps.
- Remediation actions are recommendations only; the app cannot access customer systems.
- Hash-chain checks cover recorded audit metadata and evidence references. They do not prove deletion from the underlying systems.
- Example organization and activity labels are illustrative.

Run the challenge's structural validation with `node code/validate-output.js` after generating `output.csv`.
