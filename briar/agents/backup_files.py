"""BackupFiles Agent — exposed backup and source code files"""
from urllib.parse import urljoin, urlparse
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class BackupFilesAgent:
    """Probes for exposed backup/source files derived from the target URL and common names."""

    SUFFIXES = ["~", ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
                ".zip", ".tar.gz", ".sql", ".back"]

    COMMON = ["backup.zip", "backup.sql", "db.sql", "www.zip", "site.tar.gz",
              "config.php.bak", ".DS_Store"]

    HIGH_EXT = (".sql", ".zip", ".tar.gz", "dump")

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "BackupFiles"

    def _sev_for(self, name):
        low = name.lower()
        return "High" if any(ext in low for ext in self.HIGH_EXT) else "Medium"

    def _is_real_backup(self, resp, baseline_len, baseline_ct):
        if resp.status_code != 200:
            return False
        text = resp.text or ""
        clen = resp.headers.get("Content-Length")
        ctype = resp.headers.get("Content-Type", "").lower()

        if clen is not None and clen.strip() in ("", "0"):
            return False
        if not text and not clen:
            return False

        # Binary / archive / dump markers
        if ctype.startswith("application/") and "html" not in ctype and "xhtml" not in ctype:
            return True
        if text[:2] == "PK":  # zip magic
            return True
        upper = text.upper()
        if any(m in upper for m in ("CREATE TABLE", "INSERT INTO", "DROP TABLE", "DB_CONNECTION", "MYSQL DUMP")):
            return True

        # Avoid false positives: HTML pages matching the normal site response
        if "html" in ctype or "<html" in text.lower():
            if baseline_len and abs(len(text) - baseline_len) < 64:
                return False
            return False
        return False

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        candidates = []
        try:
            parsed = urlparse(url)
            root = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else url
            path = parsed.path or "/"
            base_name = path.rstrip("/").rsplit("/", 1)[-1]
            if not base_name or "." not in base_name:
                base_name = "index.php"

            # Baseline for false-positive comparison
            baseline_len, baseline_ct = 0, ""
            try:
                base_resp = self.http.get(url)
                baseline_len = len(base_resp.text or "")
                baseline_ct = base_resp.headers.get("Content-Type", "").lower()
            except Exception:
                pass

            base_full = urljoin(root, path.lstrip("/")) if path != "/" else urljoin(root, base_name)
            for suffix in self.SUFFIXES:
                candidates.append(base_full + suffix)
            for name in self.COMMON:
                candidates.append(urljoin(root, name))

            seen = set()
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                try:
                    resp = self.http.get(candidate)
                    if self._is_real_backup(resp, baseline_len, baseline_ct):
                        fname = urlparse(candidate).path.rsplit("/", 1)[-1]
                        findings.append({
                            "type": f"Exposed backup/source file: {fname}",
                            "severity": self._sev_for(fname),
                            "agent": self.name,
                            "url": candidate,
                            "evidence": f"HTTP 200, Content-Type: {resp.headers.get('Content-Type','?')}",
                        })
                except Exception:
                    pass
        except Exception:
            pass

        analysis = f"BackupFiles scan complete for {url}\n\n"
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
        result["type"] = "Exposed Backup/Source Files"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
