"""OpenRedirect Agent — open redirect scanner via redirect-style params"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient

try:
    from briar.core.params import SSRF as REDIRECT_PARAMS
except Exception:
    REDIRECT_PARAMS = [
        "url", "redirect", "next", "goto", "return", "dest",
        "link", "target", "uri", "path", "forward", "continue",
    ]


class OpenRedirectAgent:
    """Discovers open redirect vulnerabilities with real payload injection"""

    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "https://target%2eevil.com",
    ]
    REDIRECT_CODES = (301, 302, 303, 307, 308)
    AUTH_HINTS = ("login", "logout", "auth", "sso", "oauth", "signin", "callback")

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "OpenRedirect"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        is_auth_flow = any(h in url.lower() for h in self.AUTH_HINTS)

        for param in REDIRECT_PARAMS[:12]:
            for payload in self.PAYLOADS:
                try:
                    resp = self.http.get(url, params={param: payload}, allow_redirects=False)
                    if resp.status_code not in self.REDIRECT_CODES:
                        continue
                    location = resp.headers.get("Location", "")
                    if self._points_to_evil(location):
                        findings.append({
                            "type": "Open Redirect",
                            "severity": "High" if is_auth_flow else "Medium",
                            "param": param,
                            "payload": payload,
                            "evidence": f"Location: {location}",
                            "status": resp.status_code,
                            "auth_flow": is_auth_flow,
                        })
                        break
                except Exception:
                    pass

        analysis = f"OpenRedirect scan complete for {url}\n\n"
        if findings:
            analysis += f"**{len(findings)} issues found:**\n\n"
            for f in findings:
                analysis += f"- {f.get('type','?')} ({f.get('severity','?')}) via {f.get('param','?')}={f.get('payload','?')}\n"
        else:
            analysis += "No issues detected.\n"
        analysis += "\n---\n\nLLM analysis:\n"
        result = self.analyzer.analyze_endpoint(url, "GET", tech_context=tech_context, source_hint=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Open Redirect"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _points_to_evil(location: str) -> bool:
        if not location:
            return False
        loc = location.strip().lower()
        prefixes = (
            "https://evil.com", "http://evil.com", "//evil.com",
            "/\\evil.com", "https:evil.com", "https://target%2eevil.com",
        )
        return any(loc.startswith(p) for p in prefixes)

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
