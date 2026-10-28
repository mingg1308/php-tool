"""
LLM-assisted Verification Engine supporting OpenAI, Gemini, and local Ollama.
"""

import os
import json
import re
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
            if self.provider == "openai":
                raw_response = self._call_openai(user_prompt)
            elif self.provider == "gemini":
                raw_response = self._call_gemini(user_prompt)
            elif self.provider == "ollama":
                raw_response = self._call_ollama(user_prompt)
            else:
                return None

            parsed = self._parse_llm_json(raw_response)
            if parsed is None:
                self.last_error = "LLM response did not match the required JSON schema."
            return parsed
        except Exception as e:
            message = str(e)
            if self.api_key:
                message = message.replace(self.api_key, "[REDACTED]")
            self.last_error = f"{type(e).__name__}: {message}"
            return None

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

        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            model_name=self.model,
            system_instruction=SYSTEM_PROMPT,
            generation_config={"response_mime_type": "application/json"}
        )
        response = model.generate_content(prompt, request_options={"timeout": 120, "retry": None})
        return response.text

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

        # Clean markdown code block wraps if any
        cleaned = raw_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
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
            return None
