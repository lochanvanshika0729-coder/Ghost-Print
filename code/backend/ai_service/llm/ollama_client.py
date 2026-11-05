from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OllamaError(RuntimeError):
    """Safe-to-return local model error; never contains prompt or evidence text."""


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: float = 240, embedding_model: str = "nomic-embed-text"):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.embedding_model = embedding_model
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict | None = None, timeout: float | None = None) -> dict:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(f"{self.base_url}{path}", data=data,
                          headers={"Content-Type": "application/json"}, method=method)
        try:
            with urlopen(request, timeout=timeout or self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise OllamaError(f"Ollama returned HTTP {exc.code}.") from None
        except (URLError, TimeoutError, OSError):
            raise OllamaError("Ollama is unavailable or timed out.") from None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise OllamaError("Ollama returned malformed JSON.") from None

    def health(self) -> dict:
        try:
            payload = self._request("GET", "/api/tags", timeout=min(self.timeout, 4))
            names = [str(item.get("name", "")) for item in payload.get("models", [])]
            return {"available": True, "model": self.model, "model_installed": self.model in names,
                    "installed_models": names[:40], "base_url": self.base_url}
        except OllamaError as exc:
            return {"available": False, "model": self.model, "model_installed": False,
                    "installed_models": [], "base_url": self.base_url, "message": str(exc)}

    def chat_json(self, messages: list[dict], schema: dict, max_tokens: int = 700) -> tuple[dict, dict]:
        response = self._request("POST", "/api/chat", {
            "model": self.model,
            "messages": messages,
            "format": schema,
            "stream": False,
            "think": False,
            "options": {"temperature": 0, "num_predict": max(64, min(max_tokens, 1600))},
        })
        try:
            value = json.loads(response["message"]["content"])
            if not isinstance(value, dict):
                raise ValueError("JSON root must be an object")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise OllamaError("Ollama response did not match the requested JSON format.") from None
        usage = {key: response[key] for key in ("prompt_eval_count", "eval_count", "total_duration") if key in response}
        return value, usage

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        payload = self._request("POST", "/api/embed", {
            "model": self.embedding_model, "input": texts, "truncate": True,
        })
        vectors = payload.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise OllamaError("Ollama embedding response was invalid.")
        return vectors
