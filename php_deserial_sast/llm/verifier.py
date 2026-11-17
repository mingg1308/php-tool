"""
LLM-assisted Verification Engine supporting OpenAI, Gemini, and local Ollama.
"""

import os
import json
import re
import time
from typing import Optional
import httpx
from php_deserial_sast.models import Finding, LLMVerificationResult
from php_deserial_sast.llm.prompts import SYSTEM_PROMPT, build_verification_prompt
from php_deserial_sast.llm.slicer import CodeSlicer
from php_deserial_sast.core.symbol_table import ProjectSymbolTable


class LLMVerifier:
    """Verifies SAST candidate findings using LLM APIs to eliminate False Positives."""

    def __init__(
        self,
        provider: str = "openai",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        ollama_url: str = "http://localhost:11434",
        symbol_table: Optional[ProjectSymbolTable] = None
    ):
        self.provider = provider.lower()
        provider_env_keys = {
            "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }
        env_key = provider_env_keys.get(self.provider)
        self.api_key = api_key or (os.getenv(env_key) if env_key else None)
        self.last_error: Optional[str] = None
        self.ollama_url = ollama_url
        self.slicer = CodeSlicer(symbol_table)
        self.gemini_max_attempts = max(1, int(os.getenv("GEMINI_MAX_ATTEMPTS", "5")))
        self.gemini_retry_base_seconds = max(0.0, float(os.getenv("GEMINI_RETRY_BASE_SECONDS", "2")))
        self.gemini_min_interval_seconds = max(0.0, float(os.getenv("GEMINI_MIN_INTERVAL_SECONDS", "0.8")))
        self._gemini_last_request_at = 0.0

        if not model:
            if self.provider == "openai":
                self.model = "gpt-4o-mini"
            elif self.provider == "gemini":
                self.model = "gemini-3.6-flash"
            elif self.provider == "ollama":
                self.model = "qwen2.5-coder:7b"
            else:
                self.model = "gpt-4o-mini"
        else:
            self.model = model

    def verify_finding(self, finding: Finding) -> Optional[LLMVerificationResult]:
        """Send code context of finding to LLM and parse verification response."""
        self.last_error = None
        code_slice = self.slicer.slice_finding(finding)
        chain_details = finding.gadget_chain.payload_blueprint if finding.gadget_chain else ""
        user_prompt = build_verification_prompt(
            finding.title,
            finding.vuln_type.value,
            code_slice,
            chain_details
        )

        try:
            if self.provider not in {"openai", "gemini", "ollama"}:
                return None

            raw_response = self._call_provider(user_prompt)
            parsed = self._parse_llm_json(raw_response)
            if parsed is not None:
                return parsed

            # A single format-repair retry helps with providers that return
            # valid content surrounded by prose or omit JSON-only formatting.
            repair_prompt = (
                user_prompt
                + "\n\nYour previous response did not match the required output format. "
                + "Return exactly one JSON object and no Markdown or surrounding text. "
                + "Required fields: is_vulnerable (boolean), confidence_score (number from 0 to 1), "
                + "verdict (CONFIRMED, LIKELY, NEEDS_CONTEXT, or FALSE_POSITIVE), reachability (string), "
                + "sanitization (string), exploitability (string), reasoning (string), "
                + "exploitability_assessment (string), prerequisites (array of strings), "
                + "suggested_poc (string or null), remediation (string or null)."
            )
            repaired_response = self._call_provider(repair_prompt)
            parsed = self._parse_llm_json(repaired_response)
            if parsed is None:
                self.last_error = (
                    "LLM response did not match the required JSON schema after one format-repair retry."
                )
            return parsed
        except Exception as e:
            message = str(e)
            if self.api_key:
                message = message.replace(self.api_key, "[REDACTED]")
            self.last_error = f"{type(e).__name__}: {message}"
            return None

    def _call_provider(self, prompt: str) -> str:
        """Call the configured provider using a shared dispatch path."""
        if self.provider == "openai":
            return self._call_openai(prompt)
        if self.provider == "gemini":
            return self._call_gemini(prompt)
        if self.provider == "ollama":
            return self._call_ollama(prompt)
        raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def _call_openai(self, prompt: str) -> str:
        """Invoke OpenAI Chat Completion API."""
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in environment or arguments.")

        import openai
        client = openai.OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        return response.choices[0].message.content or ""

    def _call_gemini(self, prompt: str) -> str:
        """Invoke Google Gemini Generative AI API."""
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment or arguments.")
        model_id = self.model.removeprefix("models/")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1},
        }
        if model_id.startswith("gemini-2.5-flash"):
            payload["generationConfig"]["thinkingConfig"] = {"thinkingBudget": 0}
        # The direct endpoint avoids stale proxy retries. Transient service and
        # quota responses are retried with bounded exponential backoff. A small
        # configurable interval also prevents a project with many HIGH findings
        # from sending a burst of requests.
        retryable_statuses = {429, 500, 502, 503, 504}
        with httpx.Client(trust_env=False, timeout=httpx.Timeout(90.0, connect=10.0)) as client:
            for attempt in range(self.gemini_max_attempts):
                elapsed = time.monotonic() - self._gemini_last_request_at
                wait_before_request = self.gemini_min_interval_seconds - elapsed
                if wait_before_request > 0:
                    time.sleep(wait_before_request)
                response = client.post(url, headers={"x-goog-api-key": self.api_key}, json=payload)
                self._gemini_last_request_at = time.monotonic()
                if response.status_code not in retryable_statuses:
                    response.raise_for_status()
                    break
                if attempt + 1 >= self.gemini_max_attempts:
                    response.raise_for_status()
                retry_after = response.headers.get("Retry-After")
                try:
                    retry_after_seconds = float(retry_after) if retry_after else 0.0
                except ValueError:
                    retry_after_seconds = 0.0
                backoff = self.gemini_retry_base_seconds * (2 ** attempt)
                time.sleep(max(retry_after_seconds, backoff))
        candidates = response.json().get("candidates", [])
        if not candidates:
            raise ValueError("Gemini returned no candidates.")
        parts = candidates[0].get("content", {}).get("parts", [])
        raw_text = "".join(part.get("text", "") for part in parts)
        if not raw_text:
            raise ValueError("Gemini returned no text content.")
        return raw_text

    def _call_ollama(self, prompt: str) -> str:
        """Invoke local Ollama server."""
        url = f"{self.ollama_url}/api/generate"
        payload = {
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1}
        }
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")

    def _parse_llm_json(self, raw_text: str) -> Optional[LLMVerificationResult]:
        """Extract and parse structured JSON from LLM output."""
        if not raw_text:
            return None

        cleaned = raw_text.strip().lstrip("\ufeff")
        candidates = re.findall(
            r"```(?:json)?\s*(.*?)```", cleaned, flags=re.IGNORECASE | re.DOTALL
        )
        candidates.append(cleaned)
        decoder = json.JSONDecoder()

        for candidate in candidates:
            # Accept a JSON object even when the provider adds a short preface
            # or trailing text; do not treat arbitrary prose as a valid result.
            for match in re.finditer(r"\{", candidate):
                try:
                    data, _ = decoder.raw_decode(candidate[match.start():])
                except json.JSONDecodeError:
                    continue
                if not isinstance(data, dict):
                    continue

                is_vulnerable = data.get("is_vulnerable")
                if isinstance(is_vulnerable, str):
                    normalized_bool = is_vulnerable.strip().lower()
                    if normalized_bool in {"true", "false"}:
                        data["is_vulnerable"] = normalized_bool == "true"

                confidence = data.get("confidence_score")
                if isinstance(confidence, str):
                    normalized_confidence = confidence.strip()
                    is_percent = normalized_confidence.endswith("%")
                    if is_percent:
                        normalized_confidence = normalized_confidence[:-1].strip()
                    try:
                        data["confidence_score"] = float(normalized_confidence) / (100 if is_percent else 1)
                    except ValueError:
                        pass

                prerequisites = data.get("prerequisites")
                if isinstance(prerequisites, str):
                    data["prerequisites"] = [prerequisites]

                try:
                    verdict = data.get("verdict")
                    if verdict not in {"CONFIRMED", "LIKELY", "NEEDS_CONTEXT", "FALSE_POSITIVE"}:
                        verdict = "LIKELY" if data.get("is_vulnerable") else "NEEDS_CONTEXT"
                    return LLMVerificationResult(
                        is_vulnerable=data["is_vulnerable"],
                        confidence_score=data["confidence_score"],
                        verdict=verdict,
                        reachability=str(data.get("reachability", "UNKNOWN")),
                        sanitization=str(data.get("sanitization", "UNKNOWN")),
                        exploitability=str(data.get("exploitability", "UNKNOWN")),
                        reasoning=str(data.get("reasoning", "")),
                        exploitability_assessment=str(data.get("exploitability_assessment", "UNKNOWN")),
                        prerequisites=list(data.get("prerequisites", [])),
                        suggested_poc=data.get("suggested_poc"),
                        remediation=data.get("remediation")
                    )
                except Exception:
                    continue

        return None
