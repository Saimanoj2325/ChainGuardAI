"""Verification stages.

LLMVerifier: OpenAI-compatible chat completion against NVIDIA NIM. The prompt contains ONLY the extracted
evidence for one finding (function source, flagged lines, dependency path, detector message). The model must
answer strict JSON {"verdict": "supported|refuted|uncertain", "explanation": "..."}; anything else → error.
No key → not_run. Never fabricates a verdict.

EVMValidator: calls chainguard_sandbox.api.validate(...) if the sandbox provides it; else not_run.
"""
from __future__ import annotations

import json
import logging
import re

import httpx

from chainguard_contract.models import EVMVerdict, Finding, LLMVerdict

from .analyzers.sandbox import SandboxClient
from .config import Settings

log = logging.getLogger("chainguard.verify")

SYSTEM_PROMPT = (
    "You are a smart-contract security verifier. You are given ONLY an extracted evidence bundle for one candidate "
    "vulnerability: the function source with line numbers, the flagged lines, a dependency path and the detector "
    "message. Judge ONLY from this evidence; do not assume code you cannot see. If the evidence is insufficient, "
    "answer \"uncertain\". Respond with a single JSON object and nothing else: "
    "{\"verdict\": \"supported\" | \"refuted\" | \"uncertain\", \"explanation\": \"<= 3 sentences citing line numbers\"}"
)


def build_evidence_prompt(f: Finding, function_source: str) -> str:
    lines = ", ".join(f"{r.start}-{r.end}" if r.start != r.end else str(r.start) for r in f.evidence.lines) or "n/a"
    parts = [
        f"Candidate: {f.vuln_class.value} — {f.title}",
        f"Contract: {f.contract_name or 'unknown'}; Function: {f.function_name or 'unknown'}",
        f"Flagged lines: {lines}",
        "Dependency path:\n" + ("\n".join(f"- {s}" for s in f.evidence.dependency_path) or "- (none)"),
        f"Detector message: {f.evidence.tool_output or f.description}",
        "Function source:\n```solidity\n" + (function_source or f.evidence.snippet or "(unavailable)") + "\n```",
    ]
    return "\n\n".join(parts)


_JSON_OBJ = re.compile(r"\{.*\}", re.S)


def parse_verdict(text: str) -> tuple[LLMVerdict, str]:
    """Strict parse. Accepts a bare JSON object, optionally wrapped in a ```json fence. Raises ValueError otherwise."""
    t = (text or "").strip()
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", t, re.S)
    if fence:
        t = fence.group(1).strip()
    if not (t.startswith("{") and t.endswith("}")):
        raise ValueError("LLM response is not a single JSON object")
    obj = json.loads(t)
    if not isinstance(obj, dict):
        raise ValueError("LLM JSON is not an object")
    v = obj.get("verdict")
    exp = obj.get("explanation")
    if v not in ("supported", "refuted", "uncertain"):
        raise ValueError(f"invalid verdict {v!r}")
    if not isinstance(exp, str) or not exp.strip():
        raise ValueError("missing explanation")
    return LLMVerdict(v), exp.strip()[:2000]


class LLMVerifier:
    name = "llm-nim"

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        self.s = settings
        self.transport = transport

    def available(self) -> bool:
        return bool(self.s.llm_api_key)

    @property
    def version(self) -> str:
        return self.s.llm_model

    def verify(self, f: Finding, function_source: str) -> tuple[LLMVerdict, str]:
        if not self.available():
            return LLMVerdict.not_run, "No LLM API key configured (NIM_API_KEY / CG_LLM_API_KEY)."
        body = {
            "model": self.s.llm_model, "temperature": 0.0, "max_tokens": 400,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": build_evidence_prompt(f, function_source)}],
        }
        try:
            with httpx.Client(base_url=self.s.llm_base_url, timeout=self.s.llm_timeout_s, transport=self.transport) as c:
                r = c.post("/chat/completions", json=body, headers={"Authorization": f"Bearer {self.s.llm_api_key}"})
            if r.status_code != 200:
                return LLMVerdict.error, f"LLM HTTP {r.status_code}: {r.text[:200]}"
            msg = r.json()["choices"][0]["message"]
            content = msg.get("content") or msg.get("reasoning_content") or ""
            return parse_verdict(content)
        except (ValueError, KeyError, IndexError, TypeError) as e:
            return LLMVerdict.error, f"Unparseable LLM response: {e}"[:500]
        except httpx.HTTPError as e:
            return LLMVerdict.error, f"LLM request failed: {type(e).__name__}: {e}"[:500]


class EVMValidator:
    name = "evm-sandbox"

    def __init__(self, client: SandboxClient):
        self.client = client

    def available(self) -> bool:
        return self.client.has_validate()

    def validate(self, source: str, filename: str, f: Finding) -> tuple[EVMVerdict, str]:
        if not self.available():
            return EVMVerdict.not_run, "EVM validation unavailable (sandbox validate() not installed)."
        try:
            res = self.client.validate(source, filename, f.model_dump(mode="json"))
            status = str(res.get("status", "error"))
            if status not in ("confirmed", "not_reproduced", "not_applicable", "error"):
                return EVMVerdict.error, f"sandbox returned unknown status {status!r}"
            return EVMVerdict(status), str(res.get("details") or "")[:2000]
        except Exception as e:  # noqa: BLE001
            return EVMVerdict.error, f"validate() raised {type(e).__name__}: {e}"[:500]
