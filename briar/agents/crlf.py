"""CRLF Agent — CRLF injection / HTTP response splitting detection"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient
from briar.core.params import SSRF, INJECTION


class CRLFAgent:
    """Detects CRLF injection via reflected response headers or body"""

    PAYLOADS = [
        "%0d%0aSet-Cookie:briar=injected",
        "%0d%0aX-Injected:briar",
        "%0a%0dX-Injected:briar",
        "\r\nX-Injected:briar",
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "CRLF"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        params = []
        for p in SSRF + INJECTION:
            if p not in params:
                params.append(p)

        try:
            for param in params[:14]:
                hit = False
                for payload in self.PAYLOADS:
                    result = self.http.send_payload(url, param, payload)
                    if "error" in result:
                        continue
                    headers = result.get("headers", {}) or {}
                    text = result.get("text_snippet", "")

                    # Confirmed CRLF: injected header lands in response headers
                    injected_header = any(k.lower() == "x-injected" for k in headers)
                    set_cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
                    cookie_inject = "briar=injected" in str(set_cookie)

                    if injected_header or cookie_inject:
                        findings.append({
                            "type": "CRLF Injection (header injected)",
                            "severity": "High",
                            "param": param,
                            "payload": payload,
                            "marker": "X-Injected" if injected_header else "Set-Cookie:briar=injected",
                            "status": result.get("status"),
                        })
                        hit = True
                        break

                    # Reflected in body without encoding -> lower confidence
                    if "X-Injected:briar" in text or "Set-Cookie:briar=injected" in text:
                        findings.append({
                            "type": "CRLF reflection in body",
                            "severity": "Low",
                            "param": param,
                            "payload": payload,
                            "marker": "reflected_unescaped",
                            "status": result.get("status"),
                        })
                if hit:
                    continue
        except Exception:
            pass

        analysis = f"CRLF scan complete for {url}\n\n"
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
        result["type"] = "CRLF Injection / Response Splitting"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        order = ["Critical", "High", "Medium", "Low", "Info"]
        for s in order:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
