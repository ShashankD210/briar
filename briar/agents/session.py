"""Session Agent — session management and cookie security flag detection"""
from urllib.parse import urlparse
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


class SessionAgent:
    """Detects insecure session cookie configuration (Secure/HttpOnly/SameSite)"""

    SESSION_HINTS = (
        "sess", "sid", "token", "auth", "jwt",
        "phpsessid", "jsessionid", "connect.sid",
    )

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "Session"

    def _is_session_cookie(self, name: str) -> bool:
        low = name.lower()
        return any(hint in low for hint in self.SESSION_HINTS)

    def _set_cookie_for(self, raw_set_cookie: str, cookie_name: str) -> str:
        """Find the raw Set-Cookie directive matching a given cookie name"""
        for chunk in raw_set_cookie.split(","):
            head = chunk.split("=", 1)[0].strip().lower()
            if head == cookie_name.lower():
                return chunk
        # Fall back to a substring match on the whole header
        if cookie_name.lower() in raw_set_cookie.lower():
            return raw_set_cookie
        return ""

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        try:
            resp = self.http.get(url)
            is_https = urlparse(url).scheme == "https"
            raw_set_cookie = resp.headers.get("Set-Cookie", "")

            for cookie in resp.cookies:
                if not self._is_session_cookie(cookie.name):
                    continue

                raw = self._set_cookie_for(raw_set_cookie, cookie.name)
                raw_low = raw.lower()

                # Secure: prefer cookie attr, fall back to raw header
                secure = cookie.secure or "secure" in raw_low
                if is_https and not secure:
                    findings.append({
                        "type": "Session Cookie — Missing Secure Flag",
                        "severity": "Medium",
                        "cookie": cookie.name,
                        "missing_flag": "Secure",
                        "set_cookie": raw,
                    })

                # HttpOnly: not exposed on RequestsCookieJar directly,
                # use the rest dict and the raw header
                http_only = (
                    cookie.has_nonstandard_attr("HttpOnly")
                    or cookie.has_nonstandard_attr("httponly")
                    or "httponly" in raw_low
                )
                if not http_only:
                    findings.append({
                        "type": "Session Cookie — Missing HttpOnly Flag",
                        "severity": "Medium",
                        "cookie": cookie.name,
                        "missing_flag": "HttpOnly",
                        "set_cookie": raw,
                    })

                # SameSite: absent or explicitly None
                samesite_none = "samesite=none" in raw_low
                samesite_present = "samesite=" in raw_low
                if not samesite_present or samesite_none:
                    findings.append({
                        "type": "Session Cookie — Missing or None SameSite",
                        "severity": "Low",
                        "cookie": cookie.name,
                        "missing_flag": "SameSite",
                        "set_cookie": raw,
                    })
        except Exception:
            pass

        analysis = f"Session scan complete for {url}\n\n"
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
        result["type"] = "Session Management"
        result["severity"] = self._severity(findings)
        return result

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
