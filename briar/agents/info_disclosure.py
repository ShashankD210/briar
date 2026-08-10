"""Info Disclosure Agent — exposed debug, phpinfo, stack traces 🕵️"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient

class InfoDisclosureAgent:
    """Detects information disclosure through misconfigured endpoints."""

    INFO_PATHS = [
        "/phpinfo.php", "/info.php", "/php_info.php", "/test.php",
        "/.DS_Store", "/.git/HEAD", "/.svn/entries",
        "/server-status", "/server-info", "/status",
        "/debug", "/debug/default", "/debug/pprof",
        "/actuator", "/actuator/mappings", "/actuator/env",
        "/trace", "/trace.axd", "/elmah.axd",
        "/web.config", "/web.config.bak", "/.htaccess",
        "/error", "/errors", "/error.log",
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/composer.json", "/composer.lock", "/Gemfile.lock",
        "/nginx-status", "/stub_status",
    ]

    ERROR_PATTERNS = [
        (r"Stack trace:", "Stack trace exposed"),
        (r"Traceback \(most recent call last\)", "Python traceback"),
        (r"Fatal error:", "PHP fatal error"),
        (r"Warning:.*on line \d+", "PHP warning"),
        (r"Notice:.*on line \d+", "PHP notice"),
        (r"PDOException", "DB exception"),
        (r"SQLSTATE", "SQL error exposed"),
        (r"Microsoft OLE DB", "DB provider leak"),
        (r"at org\.apache", "Java stack trace"),
        (r"Exception in thread", "Java exception"),
        (r"node_modules/", "Node path leak"),
        (r"\.(js|ts|jsx):\d+:\d+", "JS source path leak"),
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=8)
        self.name = "InfoDisclosure"

    def scan(self, url: str, **kwargs) -> dict:
        findings = []
        base = url.rstrip("/")

        # 1. Scan known info disclosure paths
        for path in self.INFO_PATHS[:25]:
            try:
                r = self.http.get(f"{base}{path}")
                if r.status_code == 200 and len(r.text) > 20:
                    import re
                    sev = "High" if any(x in path for x in [".env", ".git", ".svn", "actuator/env"]) else "Medium"
                    findings.append({
                        "type": f"Info Disclosure: {path}",
                        "severity": sev,
                        "agent": self.name,
                        "path": path,
                        "status": r.status_code,
                        "confirmed": True,
                        "poc": f"curl '{base}{path}'",
                    })
            except: pass

        # 2. Check main page for error disclosures
        try:
            r = self.http.get(base)
            html = r.text[:5000]
            headers = str(r.headers)
            import re
            for pattern, desc in self.ERROR_PATTERNS:
                if re.search(pattern, html + headers):
                    findings.append({
                        "type": f"Info Disclosure: {desc}",
                        "severity": "Medium",
                        "agent": self.name,
                        "confirmed": True,
                        "analysis": f"Error/stack trace disclosed in response: {desc}",
                    })
                    break
        except: pass

        # 3. Check server header for version info
        try:
            server = r.headers.get("Server", "")
            if server and len(server) > 10:  # Has version info
                findings.append({
                    "type": "Info Disclosure: Server version",
                    "severity": "Low",
                    "agent": self.name,
                    "server": server,
                    "confirmed": True,
                })
        except: pass

        # 4. X-Powered-By
        try:
            powered = r.headers.get("X-Powered-By", "")
            if powered:
                findings.append({
                    "type": "Info Disclosure: X-Powered-By",
                    "severity": "Low",
                    "agent": self.name,
                    "header": powered,
                    "confirmed": True,
                })
        except: pass

        total = len(findings)
        analysis = f"Info disclosure scan: {total} issues found.\n"
        for f in findings:
            analysis += f"- [{f['severity']}] {f['type']}\n"

        result = self.analyzer.analyze_endpoint(url, analysis=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Info Disclosure"
        result["severity"] = "High" if any(f["severity"] == "High" for f in findings) else ("Medium" if findings else "Info")
        return result
