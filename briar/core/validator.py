"""Briar Exploit Validator — rejoue les findings pour confirmer ou jeter 🎯"""
from briar.core.http import HTTPClient

class ExploitValidator:
    """Replays payloads to confirm findings before reporting them.
    
    Shannon-style: no exploit, no report.
    """

    def __init__(self):
        self.http = HTTPClient(timeout=10)
        self.results = []

    @staticmethod
    def _replayable(finding: dict):
        """Return (param, payload, target_url, method, marker) to replay — from the
        finding itself or, failing that, from its first concrete real_findings entry."""
        candidates = [finding] + list(finding.get("real_findings") or [])
        for c in candidates:
            if c.get("param") and c.get("payload"):
                return (c["param"], c["payload"],
                        finding.get("url") or c.get("url"),
                        c.get("method", "GET"), c.get("marker"))
        return (None, None, None, "GET", None)

    def validate(self, finding: dict, base_url: str) -> dict:
        """Replay the payload on the REAL endpoint and only confirm if the vuln
        marker is reproduced (SQL error / reflection / file leak / stored marker)."""
        param, payload, target, method, marker = self._replayable(finding)
        target = target or base_url
        if not param or not payload:
            return {**finding, "confirmed": False, "replay_reason": "no_param_or_payload"}
        try:
            resp = self.http.send_payload(target, param, payload, method)
            if "error" in resp:
                return {**finding, "confirmed": False, "replay_reason": "http_error"}
            text = resp.get("text_snippet", "")
            confirmed, how = False, ""
            if self.http.detect_error(text):
                confirmed, how = True, "database/error signature reproduced"
            elif self.http.has_reflection(text, payload):
                confirmed, how = True, "payload reflected unescaped on replay"
            elif self.http.detect_file_content(text):
                confirmed, how = True, "file content leaked on replay"
            elif marker and marker in text:
                confirmed, how = True, "vulnerability marker reproduced"
            finding["poc"] = self._build_curl(target, param, payload, method)
            finding["replay_status"] = resp["status"]
            finding["confirmed"] = confirmed
            finding["replay_reason"] = how or "marker not reproduced on replay"
        except Exception as e:
            finding["confirmed"] = False
            finding["replay_reason"] = str(e)
        return finding

    def validate_all(self, findings: list, base_url: str) -> list:
        """Replay High/Critical findings; downgrade the ones that don't reproduce."""
        validated = []
        for f in findings:
            sev = f.get("severity", "Info")
            param, payload, _, _, _ = self._replayable(f)
            if sev in ("Critical", "High") and param and payload:
                v = self.validate(f, base_url)
                if not v.get("confirmed"):
                    v["severity"] = "Medium"
                    v["type"] = f"{v.get('type', '?')} (unconfirmed)"
                validated.append(v)
            else:
                validated.append(f)
        self.results = validated
        return validated

    def _build_curl(self, url: str, param: str, payload: str, method: str = "GET") -> str:
        """Generate copy-paste curl command for PoC."""
        from urllib.parse import quote
        encoded = quote(payload, safe='')
        if method.upper() == "GET":
            return f"curl -s '{url}?{param}={encoded}'"
        elif method.upper() == "POST":
            return f"curl -s -X POST '{url}' -d '{param}={encoded}'"
        return f"curl -s -X {method} '{url}?{param}={encoded}'"

    def summary(self) -> str:
        """Return a summary of validation results."""
        total = len(self.results)
        confirmed = sum(1 for r in self.results if r.get("confirmed"))
        unconfirmed = total - confirmed
        return f"Validated {total} findings: {confirmed} confirmed, {unconfirmed} unconfirmed (downgraded)"
