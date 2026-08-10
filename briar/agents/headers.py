"""Headers Agent — missing/weak security headers and clickjacking detection"""
from urllib.parse import urlparse
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class HeadersAgent:
    """Inspects HTTP response headers for missing security controls and info leaks."""

    LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "Headers"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            resp = self.http.get(url)
            headers = resp.headers
            lower = {k.lower(): v for k, v in headers.items()}
            is_https = urlparse(resp.url).scheme == "https"

            csp = lower.get("content-security-policy", "")
            if not csp:
                findings.append({
                    "type": "Missing Content-Security-Policy header",
                    "severity": "Medium",
                    "agent": self.name,
                    "header": "Content-Security-Policy",
                    "evidence": "Header absent",
                })

            xfo = lower.get("x-frame-options", "")
            if not xfo and "frame-ancestors" not in csp.lower():
                findings.append({
                    "type": "Clickjacking: no X-Frame-Options or CSP frame-ancestors",
                    "severity": "Medium",
                    "agent": self.name,
                    "header": "X-Frame-Options",
                    "evidence": "Neither X-Frame-Options nor frame-ancestors set",
                })

            if is_https and not lower.get("strict-transport-security"):
                findings.append({
                    "type": "Missing Strict-Transport-Security header (HTTPS)",
                    "severity": "Medium",
                    "agent": self.name,
                    "header": "Strict-Transport-Security",
                    "evidence": "HSTS absent on HTTPS endpoint",
                })

            xcto = lower.get("x-content-type-options", "")
            if "nosniff" not in xcto.lower():
                findings.append({
                    "type": "Missing X-Content-Type-Options: nosniff",
                    "severity": "Low",
                    "agent": self.name,
                    "header": "X-Content-Type-Options",
                    "evidence": xcto or "Header absent",
                })

            if not lower.get("referrer-policy"):
                findings.append({
                    "type": "Missing Referrer-Policy header",
                    "severity": "Low",
                    "agent": self.name,
                    "header": "Referrer-Policy",
                    "evidence": "Header absent",
                })

            if not lower.get("permissions-policy"):
                findings.append({
                    "type": "Missing Permissions-Policy header",
                    "severity": "Low",
                    "agent": self.name,
                    "header": "Permissions-Policy",
                    "evidence": "Header absent",
                })

            for h in self.LEAK_HEADERS:
                val = lower.get(h.lower())
                if val:
                    findings.append({
                        "type": f"Information disclosure via {h} header",
                        "severity": "Low",
                        "agent": self.name,
                        "header": h,
                        "evidence": f"{h}: {val}",
                    })
        except Exception:
            pass

        analysis = f"Headers scan complete for {url}\n\n"
        if findings:
            analysis += f"**{len(findings)} issues found:**\n\n"
            for f in findings:
                analysis += f"- {f.get('type','?')} ({f.get('severity','?')})\n"
        else:
            analysis += "No issues detected.\n"
        analysis += "\n---\n\nLLM analysis:\n"
        result = self.analyzer.analyze_endpoint(url, "GET", tech_context=tech_context, source_hint=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Security Headers"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
