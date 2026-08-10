"""IDOR Agent — Insecure Direct Object Reference / BOLA detection"""
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class IDORAgent:
    """Detects IDOR / BOLA by tampering numeric object identifiers"""

    ID_PARAM_HINTS = (
        "id", "user", "userid", "uid", "account", "acct", "order",
        "doc", "document", "file", "pid", "num", "no", "key", "ref",
    )

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "IDOR"

    def _path_ids(self, path: str) -> list:
        """Return (segment_index, value) for numeric path segments"""
        segments = path.split("/")
        found = []
        for i, seg in enumerate(segments):
            if seg.isdigit():
                found.append((i, int(seg)))
        return found

    def _neighbors(self, value: int) -> list:
        """Adjacent / boundary identifiers to probe"""
        candidates = [value - 1, value + 1, 0, 1]
        seen = []
        for c in candidates:
            if c >= 0 and c != value and c not in seen:
                seen.append(c)
        return seen

    def _build_path_url(self, parsed, segments, index, new_value) -> str:
        new_segments = list(segments)
        new_segments[index] = str(new_value)
        new_path = "/".join(new_segments)
        return urlunparse(parsed._replace(path=new_path))

    def _build_param_url(self, parsed, params, target_param, new_value) -> str:
        new_params = [
            (k, str(new_value) if k == target_param else v) for k, v in params
        ]
        return urlunparse(parsed._replace(query=urlencode(new_params)))

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            parsed = urlparse(url)
            segments = parsed.path.split("/")
            params = parse_qsl(parsed.query, keep_blank_values=True)

            # Collect candidate identifiers from path and query params
            candidates = []  # (kind, locator, value)
            for index, value in self._path_ids(parsed.path):
                candidates.append(("path", index, value))
            for key, value in params:
                if value.isdigit() and (
                    key.lower() in self.ID_PARAM_HINTS
                    or any(h in key.lower() for h in self.ID_PARAM_HINTS)
                ):
                    candidates.append(("param", key, int(value)))

            for kind, locator, value in candidates:
                # Baseline request on the original identifier
                if kind == "path":
                    base_url = self._build_path_url(parsed, segments, locator, value)
                else:
                    base_url = self._build_param_url(parsed, params, locator, value)

                base_resp = self.http.get(base_url)
                base_len = len(base_resp.text)
                base_body = base_resp.text

                for neighbor in self._neighbors(value):
                    try:
                        if kind == "path":
                            test_url = self._build_path_url(
                                parsed, segments, locator, neighbor
                            )
                        else:
                            test_url = self._build_param_url(
                                parsed, params, locator, neighbor
                            )

                        test_resp = self.http.get(test_url)
                        test_len = len(test_resp.text)

                        # Different non-empty 200 content => possible unauthorized
                        # access to another resource (no access control enforced)
                        if (
                            test_resp.status_code == 200
                            and test_len > 0
                            and test_resp.text != base_body
                            and abs(test_len - base_len) > 0
                        ):
                            findings.append({
                                "type": "IDOR — Object Reference Tampering",
                                "severity": "High",
                                "location": kind,
                                "identifier": str(locator),
                                "original_value": value,
                                "tampered_value": neighbor,
                                "original_url": base_url,
                                "test_url": test_url,
                                "original_status": base_resp.status_code,
                                "test_status": test_resp.status_code,
                                "original_len": base_len,
                                "test_len": test_len,
                            })
                            break
                    except Exception:
                        pass
        except Exception:
            pass

        analysis = f"IDOR scan complete for {url}\n\n"
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
        result["type"] = "Insecure Direct Object Reference"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
