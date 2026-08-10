"""AdminPanel Agent — detects exposed admin panels and sensitive interfaces"""
from urllib.parse import urljoin

from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class AdminPanelAgent:
    """Probes common admin/management paths for exposed or protected interfaces."""

    PATHS = [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/admin/login",
        "/manager/html",
        "/phpmyadmin",
        "/adminer.php",
        "/console",
        "/.git/",
        "/jenkins",
        "/grafana",
        "/kibana",
        "/swagger-ui.html",
        "/api-docs",
    ]

    # Paths that, if 200, are almost always a direct compromise.
    HIGH_PATHS = ("/phpmyadmin", "/adminer.php", "/jenkins", "/.git/")

    MARKERS = [
        "type=\"password\"",
        "type='password'",
        "password",
        "dashboard",
        "phpmyadmin",
        "grafana",
        "swagger",
        "login",
        "<form",
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "AdminPanel"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            base = url if url.endswith("/") else url + "/"
            for path in self.PATHS:
                endpoint = urljoin(base, path.lstrip("/"))
                try:
                    resp = self.http.get(endpoint, allow_redirects=False)
                except Exception:
                    continue
                status = resp.status_code
                text = (resp.text or "").lower()

                if status in (401, 403):
                    findings.append({
                        "type": f"Admin panel present but protected: {path}",
                        "severity": "Low",
                        "agent": self.name,
                        "path": path,
                        "endpoint": endpoint,
                        "status": status,
                        "evidence": f"HTTP {status}",
                    })
                elif status == 200:
                    has_marker = any(m in text for m in self.MARKERS)
                    if path in self.HIGH_PATHS:
                        findings.append({
                            "type": f"Sensitive interface exposed: {path}",
                            "severity": "High",
                            "agent": self.name,
                            "path": path,
                            "endpoint": endpoint,
                            "status": status,
                            "evidence": "HTTP 200 on high-risk path",
                        })
                    elif has_marker:
                        findings.append({
                            "type": f"Admin panel exposed: {path}",
                            "severity": "Medium",
                            "agent": self.name,
                            "path": path,
                            "endpoint": endpoint,
                            "status": status,
                            "evidence": "HTTP 200 with login/admin marker",
                        })
        except Exception:
            pass

        analysis = f"AdminPanel scan complete for {url}\n\n"
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
        result["type"] = "Admin Panel Exposure"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
