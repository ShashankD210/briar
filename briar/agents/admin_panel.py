"""Admin Panel Finder — exposed admin interfaces 🚪"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient

class AdminPanelAgent:
    """Scans for exposed admin panels and dashboards."""

    ADMIN_PATHS = [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/phpMyAdmin", "/pma", "/mysql",
        "/grafana", "/jenkins", "/gitlab", "/redmine",
        "/api/admin", "/api-docs", "/swagger", "/swagger-ui",
        "/actuator", "/actuator/health", "/actuator/env",
        "/_ah/admin", "/console", "/manager/html",
        "/solr", "/solr/admin", "/django-admin",
        "/rails/conductor", "/sidekiq", "/resque",
        "/adminer", "/admin.php", "/login", "/signin",
        "/cpanel", "/webmail", "/roundcube",
        "/.env", "/config.json", "/config.yml",
        "/debug", "/debug/default", "/debug/pprof",
        "/metrics", "/status", "/health", "/info",
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=6)
        self.name = "AdminPanel"

    def scan(self, url: str, **kwargs) -> dict:
        findings = []
        base = url.rstrip("/")

        for path in self.ADMIN_PATHS[:30]:
            try:
                r = self.http.get(f"{base}{path}", allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    sev = "High"
                    if r.status_code == 403: sev = "Medium"
                    if path in ["/health", "/status", "/metrics", "/actuator/health"]: sev = "Low"
                    
                    findings.append({
                        "type": f"Admin Panel: {path}",
                        "severity": sev,
                        "agent": self.name,
                        "path": path,
                        "status": r.status_code,
                        "confirmed": r.status_code in [200, 403],
                    })
            except: pass

        total = len(findings)
        analysis = f"Admin panel scan: {total} endpoints found.\n"
        for f in findings:
            analysis += f"- [{f['severity']}] {f['path']} (HTTP {f['status']})\n"

        result = self.analyzer.analyze_endpoint(url, analysis=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Admin Panels"
        result["severity"] = "High" if any(f["severity"] == "High" for f in findings) else ("Medium" if findings else "Info")
        return result
