"""Cache Agent — detects web cache poisoning and cache deception"""
from urllib.parse import urljoin

from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class CacheAgent:
    """Tests unkeyed-header cache poisoning and cache deception on static-looking paths."""

    POISON_HEADERS = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-Scheme", "evil.com"),
        ("X-Host", "evil.com"),
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "Cache"

    @staticmethod
    def _cache_evidence(headers):
        """Return a list of cache indicators observed in response headers."""
        observed = []
        for h in ("X-Cache", "CF-Cache-Status", "Age"):
            if h in headers:
                observed.append(f"{h}: {headers.get(h)}")
        cc = headers.get("Cache-Control", "")
        if "public" in cc.lower():
            observed.append(f"Cache-Control: {cc}")
        return observed

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            for header, value in self.POISON_HEADERS:
                try:
                    resp = self.http.get(url, headers={header: value})
                except Exception:
                    continue
                text = resp.text or ""
                cache_evidence = self._cache_evidence(resp.headers)
                if value in text and cache_evidence:
                    findings.append({
                        "type": f"Web cache poisoning via {header}",
                        "severity": "High",
                        "agent": self.name,
                        "header": header,
                        "status": resp.status_code,
                        "evidence": f"Reflected '{value}'; cache headers: {', '.join(cache_evidence)}",
                    })

            try:
                base = url if url.endswith("/") else url + "/"
                deception_url = urljoin(base, "nonexistent.css")
                resp = self.http.get(deception_url)
                cache_evidence = self._cache_evidence(resp.headers)
                xcache = resp.headers.get("X-Cache", "")
                cached = bool(cache_evidence) or "hit" in xcache.lower()
                if resp.status_code == 200 and cached and (resp.text or "").strip():
                    findings.append({
                        "type": "Cache deception (dynamic page cached under static path)",
                        "severity": "Medium",
                        "agent": self.name,
                        "url": deception_url,
                        "status": resp.status_code,
                        "evidence": f"200 + cache headers: {', '.join(cache_evidence) or xcache}",
                    })
            except Exception:
                pass
        except Exception:
            pass

        analysis = f"Cache scan complete for {url}\n\n"
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
        result["type"] = "Web Cache Poisoning/Deception"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
