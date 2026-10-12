"""Multi-provider advisory LLM adapter supporting OpenAI-compatible, Anthropic, Gemini, and Ollama."""
import json
import logging
from typing import Dict, Any, List, Optional
import httpx
from backend.app.core.config import settings
from backend.app.models.schemas import Finding, LLMAdvisory

logger = logging.getLogger(__name__)


def _redact_secret_in_error(err_str: str) -> str:
    """Ensure no API keys, tokens, or URL secrets appear in error logs or responses."""
    if settings.llm_api_key and settings.llm_api_key in err_str:
        return err_str.replace(settings.llm_api_key, "[REDACTED_API_KEY]")
    return err_str


class LLMAdvisoryService:
    """Opt-in advisory explanations grounded strictly in deterministic posture records."""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.provider = settings.llm_provider.lower()
        self.model = settings.llm_model
        self.base_url = settings.llm_base_url.rstrip("/")
        self.timeout = settings.llm_timeout_seconds

    def generate_advisory(
        self,
        target_name: str,
        overall_score: int,
        grade: str,
        findings: List[Finding]
    ) -> LLMAdvisory:
        """Produce grounded advisory analysis from deterministic scan findings."""
        if not self.api_key and self.provider != "ollama":
            return self._build_offline_advisory(
                overall_score=overall_score,
                grade=grade,
                findings=findings,
                error="LLM_API_KEY is not configured on the server. Offline deterministic advisory active."
            )

        prompt = self._build_prompt(target_name, overall_score, grade, findings)

        try:
            raw_text = self._dispatch_provider(prompt)
            return self._parse_response(raw_text, findings)
        except Exception as exc:
            redacted = _redact_secret_in_error(str(exc))
            logger.warning(f"LLM advisory request failed: {redacted}")
            return self._build_offline_advisory(
                overall_score=overall_score,
                grade=grade,
                findings=findings,
                error=f"Provider {self.provider} request failed: {redacted}"
            )

    def _build_prompt(
        self,
        target_name: str,
        score: int,
        grade: str,
        findings: List[Finding]
    ) -> str:
        findings_summary = [
            f"- [{f.severity}] {f.title} ({f.category}, -{f.deduction_points} pts): {f.description}"
            for f in findings[:15]
        ]
        return (
            f"You are a principal cybersecurity engineer evaluating an application's security posture.\n"
            f"Audit Target: {target_name}\n"
            f"Calculated Score: {score}/100 (Grade {grade})\n\n"
            f"Deterministic Scan Findings:\n" + "\n".join(findings_summary) + "\n\n"
            "Provide an advisory threat analysis. Respond ONLY with valid JSON having the following schema:\n"
            "{\n"
            '  "executive_summary": "1-2 sentence high-level executive risk assessment",\n'
            '  "threat_analysis": "Technical analysis of potential attacker exploitation paths",\n'
            '  "prioritized_guidance": ["Step 1...", "Step 2...", "Step 3..."]\n'
            "}"
        )

    def _dispatch_provider(self, prompt: str) -> str:
        with httpx.Client(timeout=self.timeout) as client:
            if self.provider in ("openai", "openai-compatible"):
                return self._call_openai_compatible(client, prompt)
            elif self.provider == "anthropic":
                return self._call_anthropic(client, prompt)
            elif self.provider == "gemini":
                return self._call_gemini(client, prompt)
            elif self.provider == "ollama":
                return self._call_ollama(client, prompt)
            else:
                raise ValueError(f"Unsupported LLM provider '{self.provider}'")

    def _call_openai_compatible(self, client: httpx.Client, prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}" if self.api_key else ""
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a professional security posture advisor. Respond in strict JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }
        resp = client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def _call_anthropic(self, client: httpx.Client, prompt: str) -> str:
        url = f"{self.base_url}/v1/messages" if "v1" not in self.base_url else f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key or "",
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]

    def _call_gemini(self, client: httpx.Client, prompt: str) -> str:
        url = f"{self.base_url}/v1beta/models/{self.model}:generateContent"
        params = {"key": self.api_key} if self.api_key else {}
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        resp = client.post(url, headers=headers, params=params, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_ollama(self, client: httpx.Client, prompt: str) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "{}")

    def _parse_response(self, raw_text: str, findings: List[Finding]) -> LLMAdvisory:
        try:
            start = raw_text.find("{")
            end = raw_text.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(raw_text[start:end])
                return LLMAdvisory(
                    advisory_enabled=True,
                    provider=self.provider,
                    model=self.model,
                    executive_summary=parsed.get("executive_summary", "Executive evaluation completed."),
                    threat_analysis=parsed.get("threat_analysis", "Risk identified across static findings."),
                    prioritized_guidance=parsed.get("prioritized_guidance", [f.remediation for f in findings[:3]]),
                    is_fallback=False,
                    error=None
                )
        except Exception:
            pass

        return self._build_offline_advisory(
            overall_score=75,
            grade="B",
            findings=findings,
            error="Unable to parse valid JSON from provider response."
        )

    def _build_offline_advisory(
        self,
        overall_score: int,
        grade: str,
        findings: List[Finding],
        error: Optional[str] = None
    ) -> LLMAdvisory:
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")

        if crit_count > 0:
            summary = f"High-risk posture alert: {crit_count} critical deficiencies present immediate exposure."
            analysis = "Adversaries can exploit unprotected endpoints, hardcoded credentials, or insecure ciphers without privilege."
        elif high_count > 0:
            summary = f"Moderate risk posture: {high_count} high-severity findings require prioritized remediation."
            analysis = "Attackers may chain missing security headers or unpatched dependencies to escalate privileges."
        else:
            summary = f"Defensible posture achieved: Score {overall_score}/100 indicates solid baseline hardening."
            analysis = "Remaining issues are primarily preventative hardening items."

        guidance = [f.remediation for f in findings[:4]]
        if not guidance:
            guidance = ["Maintain continuous automated security scans across code and configuration changes."]

        return LLMAdvisory(
            advisory_enabled=False,
            provider="offline-deterministic",
            model="heuristic-engine",
            executive_summary=summary,
            threat_analysis=analysis,
            prioritized_guidance=guidance,
            is_fallback=True,
            error=error
        )


llm_service = LLMAdvisoryService()
