"""SSTI Agent — Server-Side Template Injection detection via math evaluation"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient
from briar.core.params import INJECTION, XSS


class SSTIAgent:
    """Detects template injection by checking for evaluated math markers"""

    # (payload, expected_marker, engine)
    PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("${7*7}", "49", "Freemarker/JSP-EL"),
        ("#{7*7}", "49", "Ruby/JSF-EL"),
        ("<%= 7*7 %>", "49", "ERB"),
        ("{{7*'7'}}", "7777777", "Jinja2"),
        ("${{7*7}}", "49", "EL-wrapped"),
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "SSTI"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        params = []
        for p in INJECTION + XSS:
            if p not in params:
                params.append(p)

        try:
            for param in params[:14]:
                hit = False
                for payload, marker, engine in self.PAYLOADS:
                    result = self.http.send_payload(url, param, payload)
                    if "error" in result:
                        continue
                    text = result.get("text_snippet", "")
                    # Confirmed only when the evaluated result shows up
                    # while the raw payload itself does not (i.e. it was rendered)
                    if marker in text and payload not in text:
                        findings.append({
                            "type": f"SSTI ({engine})",
                            "severity": "High",
                            "param": param,
                            "payload": payload,
                            "marker": marker,
                            "engine": engine,
                            "status": result.get("status"),
                        })
                        hit = True
                        break
                if hit:
                    continue
        except Exception:
            pass

        analysis = f"SSTI scan complete for {url}\n\n"
        if findings:
            analysis += f"**{len(findings)} issues found:**\n\n"
            for f in findings:
                analysis += f"- {f.get('type', '?')} ({f.get('severity', '?')})\n"
        else:
            analysis += "No issues detected.\n"
        analysis += "\n---\n\nLLM analysis:\n"

        result = self.analyzer.analyze_endpoint(url, "GET", tech_context=tech_context, source_hint=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Server-Side Template Injection"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        order = ["Critical", "High", "Medium", "Low", "Info"]
        for s in order:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
