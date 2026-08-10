"""HostHeader Agent — Host header injection / password-reset & cache poisoning scanner"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class HostHeaderAgent:
    """Discovers Host header injection vulnerabilities with real payload injection"""

    EVIL = "evil.com"
    VARIANTS = [
        {"Host": "evil.com"},
        {"X-Forwarded-Host": "evil.com"},
        {"X-Forwarded-Server": "evil.com"},
        {"X-Host": "evil.com"},
        {"Forwarded": "host=evil.com"},
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "HostHeader"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []

        # Baseline: ensure evil.com is not present without the malicious header
        baseline_text = ""
        try:
            baseline = self.http.get(url, allow_redirects=False)
            baseline_text = baseline.text
        except Exception:
            pass
        baseline_has_evil = self.EVIL in baseline_text

        for headers in self.VARIANTS:
            try:
                resp = self.http.get(url, headers=headers, allow_redirects=False)
            except Exception:
                continue

            header_name = next(iter(headers))
            location = resp.headers.get("Location", "")

            # Location header poisoning (password-reset / redirect poisoning)
            if self.EVIL in location.lower():
                findings.append({
                    "type": "Host Header Injection (Location poisoning)",
                    "severity": "High",
                    "header": header_name,
                    "payload": headers[header_name],
                    "evidence": f"Location: {location}",
                    "status": resp.status_code,
                })
                continue

            # Reflection in body (absolute links, canonical, cache poisoning)
            try:
                body = resp.text
            except Exception:
                body = ""
            if self.EVIL in body and not baseline_has_evil:
                findings.append({
                    "type": "Host Header Injection (body reflection)",
                    "severity": "Medium",
                    "header": header_name,
                    "payload": headers[header_name],
                    "evidence": "evil.com reflected in response body (absolute link/canonical)",
                    "status": resp.status_code,
                })

        analysis = f"HostHeader scan complete for {url}\n\n"
        if findings:
            analysis += f"**{len(findings)} issues found:**\n\n"
            for f in findings:
                analysis += f"- {f.get('type','?')} ({f.get('severity','?')}) via {f.get('header','?')}\n"
        else:
            analysis += "No issues detected.\n"
        analysis += "\n---\n\nLLM analysis:\n"
        result = self.analyzer.analyze_endpoint(url, "GET", tech_context=tech_context, source_hint=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Host Header Injection"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
