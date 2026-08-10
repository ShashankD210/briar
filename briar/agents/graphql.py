"""GraphQL Agent — detects exposed GraphQL endpoints and introspection leaks"""
from urllib.parse import urljoin

from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class GraphQLAgent:
    """Probes common GraphQL paths for exposure, introspection, and GraphiQL."""

    PATHS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/graphiql",
        "/graphql/console",
    ]

    INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "GraphQL"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            base = url if url.endswith("/") else url + "/"
            for path in self.PATHS:
                endpoint = urljoin(base, path.lstrip("/"))
                try:
                    resp = self.http.post(endpoint, json=self.INTROSPECTION_QUERY)
                except Exception:
                    continue
                text = resp.text or ""
                lower = text.lower()

                if any(m in text for m in ("__schema", "queryType")) or '"types"' in lower:
                    findings.append({
                        "type": "GraphQL introspection enabled",
                        "severity": "High",
                        "agent": self.name,
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "evidence": text[:300],
                    })
                elif '"data"' in lower or ('"errors"' in lower and "cannot query" in lower):
                    findings.append({
                        "type": "GraphQL endpoint exposed (introspection disabled)",
                        "severity": "Low",
                        "agent": self.name,
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "evidence": text[:300],
                    })

                try:
                    gresp = self.http.get(endpoint)
                    if "graphiql" in (gresp.text or "").lower():
                        findings.append({
                            "type": "GraphiQL interface exposed",
                            "severity": "Medium",
                            "agent": self.name,
                            "endpoint": endpoint,
                            "status": gresp.status_code,
                            "evidence": "GraphiQL IDE reachable",
                        })
                except Exception:
                    pass
        except Exception:
            pass

        analysis = f"GraphQL scan complete for {url}\n\n"
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
        result["type"] = "GraphQL Exposure"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
