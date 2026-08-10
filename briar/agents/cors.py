"""CORS Agent — Cross-Origin Resource Sharing misconfiguration detection"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class CORSAgent:
    """Detects permissive CORS policies via reflected and null origin probes"""

    EVIL_ORIGIN = "https://evil.com"

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "CORS"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            # Probe 1: arbitrary origin reflection
            resp = self.http.get(url, headers={"Origin": self.EVIL_ORIGIN})
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == self.EVIL_ORIGIN:
                if acac.lower() == "true":
                    findings.append({
                        "type": "CORS — Reflected Origin with Credentials",
                        "severity": "Critical",
                        "sent_origin": self.EVIL_ORIGIN,
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": acac,
                    })
                else:
                    findings.append({
                        "type": "CORS — Reflected Arbitrary Origin",
                        "severity": "High",
                        "sent_origin": self.EVIL_ORIGIN,
                        "access_control_allow_origin": acao,
                    })
            elif acao == "*":
                findings.append({
                    "type": "CORS — Wildcard Origin",
                    "severity": "Medium",
                    "sent_origin": self.EVIL_ORIGIN,
                    "access_control_allow_origin": acao,
                })

            # Probe 2: null origin acceptance
            try:
                null_resp = self.http.get(url, headers={"Origin": "null"})
                null_acao = null_resp.headers.get(
                    "Access-Control-Allow-Origin", ""
                )
                if null_acao.lower() == "null":
                    findings.append({
                        "type": "CORS — Null Origin Allowed",
                        "severity": "Medium",
                        "sent_origin": "null",
                        "access_control_allow_origin": null_acao,
                    })
            except Exception:
                pass
        except Exception:
            pass

        analysis = f"CORS scan complete for {url}\n\n"
        if findings:
            analysis += f"**{len(findings)} issues found:**\n\n"
            for f in findings:
                analysis += f"- {f.get('type','?')} ({f.get('severity','?')})\n"
        else:
            analysis += "No issues detected.\n"
        analysis += "\n---\n\nLLM analysis:\n"
        result = self.analyzer.analyze_endpoint(
            url, "GET", tech_context=tech_context, source_hint=analysis
        )
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "CORS Misconfiguration"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
