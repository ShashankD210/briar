"""Open Redirect Agent — unvalidated redirects 🔗"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient

class OpenRedirectAgent:
    """Discovers open redirect vulnerabilities."""

    REDIRECT_PARAMS = ["url", "redirect", "next", "return", "goto", "link", "target", 
                       "redir", "dest", "continue", "forward", "ref", "referer",
                       "callback", "return_url", "redirect_uri", "source"]

    PAYLOADS = ["//evil.com", "https:evil.com", "javascript:alert(1)", "\\evil.com",
                "https://evil.com", "http://169.254.169.254"]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=8)
        self.name = "OpenRedirect"

    def scan(self, url: str, **kwargs) -> dict:
        findings = []
        base = url.rstrip("/")

        for param in self.REDIRECT_PARAMS[:10]:
            for payload in self.PAYLOADS[:4]:
                try:
                    r = self.http.get(f"{base}", params={param: payload}, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    # Check if redirect contains our payload
                    if r.status_code in [301, 302, 303, 307, 308] and any(p in loc for p in ["evil.com", "169.254"]):
                        findings.append({
                            "type": "Open Redirect",
                            "severity": "Medium",
                            "agent": self.name,
                            "param": param,
                            "payload": payload,
                            "redirect_to": loc[:100],
                            "confirmed": True,
                            "poc": f"curl -i '{base}?{param}={payload}'",
                        })
                        break
                    # Check meta refresh redirect
                    if 'http-equiv="refresh"' in r.text.lower() and payload in r.text:
                        findings.append({
                            "type": "Open Redirect (meta refresh)",
                            "severity": "Low",
                            "agent": self.name,
                            "param": param,
                            "confirmed": True,
                        })
                        break
                except: pass
            if findings: break

        total = len(findings)
        analysis = f"Open redirect scan: {total} vulnerabilities found.\n"
        for f in findings:
            analysis += f"- [{f['severity']}] {f['type']}: param `{f['param']}` redirects to `{f.get('redirect_to','?')}`\n"
            analysis += f"  PoC: {f.get('poc','')}\n"

        result = self.analyzer.analyze_endpoint(url, analysis=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Open Redirect"
        result["severity"] = "Medium" if findings else "Info"
        return result
