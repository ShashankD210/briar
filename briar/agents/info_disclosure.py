"""InfoDisclosure Agent — leaked data, debug endpoints and exposed sensitive files"""
import re
from urllib.parse import urljoin, urlparse
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class InfoDisclosureAgent:
    """Detects verbose errors, leaked paths/secrets in HTML, and exposed debug endpoints."""

    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
    SECRET_RE = re.compile(r"(api[_-]?key|secret)", re.I)
    PATH_COMMENT_RE = re.compile(r"<!--.*?(?:/var/|/home/|/usr/|[A-Za-z]:\\|version\s*[:=]).*?-->", re.I | re.DOTALL)

    PROBES = [
        ("/.env", "DB_", "High"),
        ("/server-status", "Apache Server Status", "Medium"),
        ("/phpinfo.php", "phpinfo()", "Medium"),
        ("/debug", "DEBUG", "Medium"),
        ("/.git/config", "[core]", "High"),
        ("/actuator", '"_links"', "Medium"),
        ("/actuator/env", '"propertySources"', "High"),
        ("/.well-known/security.txt", "Contact:", "Low"),
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "InfoDisclosure"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            resp = self.http.get(url)
            text = resp.text or ""

            err = self.http.detect_error(text)
            if err:
                findings.append({
                    "type": "Verbose error / stack trace exposed",
                    "severity": "Medium",
                    "agent": self.name,
                    "url": resp.url,
                    "evidence": f"Pattern matched: {err}",
                })

            comment = self.PATH_COMMENT_RE.search(text)
            if comment:
                findings.append({
                    "type": "HTML comment leaks path/version info",
                    "severity": "Low",
                    "agent": self.name,
                    "url": resp.url,
                    "evidence": comment.group(0)[:200],
                })

            aws = self.AWS_KEY_RE.search(text)
            if aws:
                findings.append({
                    "type": "AWS access key exposed in response",
                    "severity": "High",
                    "agent": self.name,
                    "url": resp.url,
                    "evidence": aws.group(0),
                })
            elif self.SECRET_RE.search(text):
                findings.append({
                    "type": "Possible secret/api_key reference in response",
                    "severity": "Low",
                    "agent": self.name,
                    "url": resp.url,
                    "evidence": "api_key/secret keyword present in body",
                })

            emails = self.EMAIL_RE.findall(text)
            if emails:
                findings.append({
                    "type": "Email address(es) disclosed in response",
                    "severity": "Info",
                    "agent": self.name,
                    "url": resp.url,
                    "evidence": ", ".join(sorted(set(emails))[:5]),
                })
        except Exception:
            pass

        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else url
        for path, marker, sev in self.PROBES:
            try:
                candidate = urljoin(root, path.lstrip("/"))
                resp = self.http.get(candidate)
                if resp.status_code == 200 and marker.lower() in (resp.text or "").lower():
                    findings.append({
                        "type": f"Exposed endpoint: {path}",
                        "severity": sev,
                        "agent": self.name,
                        "url": resp.url,
                        "evidence": f"HTTP 200 with marker '{marker}'",
                    })
            except Exception:
                pass

        analysis = f"InfoDisclosure scan complete for {url}\n\n"
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
        result["type"] = "Information Disclosure"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
