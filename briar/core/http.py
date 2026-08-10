"""Briar HTTP Client — shared request engine for all agents 🌐"""
import os
import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, urlunparse

class HTTPClient:
    """Shared HTTP utilities for all security agents"""

    def __init__(self, timeout: int = 10):
        self.session = requests.Session()
        # Browser-like UA — a "scanner" UA gets blocked by many WAFs/CDNs, which
        # silently returns 0 pages. Override with BRIAR_USER_AGENT if needed.
        self.session.headers.update({
            "User-Agent": os.environ.get("BRIAR_USER_AGENT",
                "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        # Pentest scanners MUST NOT verify TLS certs — targets often have self-signed,
        # expired or mismatched certs (a cert error would otherwise kill the whole scan).
        self.session.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        # Global override: BRIAR_HTTP_TIMEOUT caps every agent's timeout at once
        # (the main lever against hour-long scans on slow targets).
        try:
            self.timeout = int(os.environ.get("BRIAR_HTTP_TIMEOUT") or timeout)
        except (TypeError, ValueError):
            self.timeout = timeout
        # Resilience: retry transient failures + connection pooling (safe methods only)
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            # Light retries only: retrying read-timeouts on a slow target amplifies
            # scan time massively (read=0). Just one quick connect/status retry.
            retry = Retry(total=1, connect=1, read=0, backoff_factor=0.1,
                          status_forcelist=[429, 502, 503], raise_on_status=False)
            adapter = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=32)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        except Exception:
            pass

    def get(self, url: str, params: dict = None, **kwargs) -> requests.Response:
        return self.session.get(url, params=params, timeout=self.timeout, **kwargs)

    def post(self, url: str, data: dict = None, json: dict = None, files: dict = None, **kwargs) -> requests.Response:
        return self.session.post(url, data=data, json=json, files=files, timeout=self.timeout, **kwargs)

    def send_payload(self, url: str, param: str, payload: str, method: str = "GET") -> dict:
        """Send a payload via GET or POST and return response metadata.
        GET rewrites the query so an existing param (e.g. ?cat=1) is REPLACED by the
        payload, not appended — otherwise the vulnerable value stays benign."""
        try:
            if method.upper() == "GET":
                parsed = urlparse(url)
                q = parse_qs(parsed.query, keep_blank_values=True)
                q[param] = [payload]
                target = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
                resp = self.get(target)
            else:
                resp = self.post(url, data={param: payload})
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "time": resp.elapsed.total_seconds(),
                "text_snippet": resp.text[:500],
                "headers": dict(resp.headers),
                "payload": payload,
                "param": param,
            }
        except Exception as e:
            return {"error": str(e), "payload": payload, "param": param}

    def batch_send(self, url: str, jobs: list, method: str = "GET", max_workers: int = 12) -> list:
        """Fire many payloads concurrently. jobs = [(param, payload), ...].
        Returns result dicts in the same order as jobs. This is what turns a
        144-request serial agent (minutes) into a couple of seconds."""
        from concurrent.futures import ThreadPoolExecutor
        if not jobs:
            return []
        with ThreadPoolExecutor(max_workers=min(max_workers, len(jobs))) as pool:
            return list(pool.map(lambda j: self.send_payload(url, j[0], j[1], method), jobs))

    def extract_params(self, html: str) -> list:
        """Extract input parameter names from HTML forms"""
        params = set()
        # <input name="xxx">
        params.update(re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I))
        # URL query params in href/src
        for url in re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.I):
            parsed = urlparse(url)
            params.update(parse_qs(parsed.query).keys())
        return list(params)

    def extract_forms(self, html: str) -> list:
        """Extract form metadata: action, method, inputs"""
        forms = []
        for form_match in re.finditer(r'<form[^>]*>.*?</form>', html, re.I | re.DOTALL):
            form_html = form_match.group(0)
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.I)
            uploads = bool(re.search(r'type=["\']file["\']', form_html, re.I))
            csrf = any('csrf' in i.lower() or 'token' in i.lower() or 'nonce' in i.lower() for i in inputs)
            forms.append({
                "action": urljoin("", action.group(1)) if action else "",
                "method": (method.group(1) or "GET").upper() if method else "GET",
                "inputs": inputs,
                "has_upload": uploads,
                "has_csrf_token": csrf,
            })
        return forms

    def has_reflection(self, response_text: str, payload: str) -> bool:
        """Check if a payload is reflected in the response (for XSS detection)"""
        # Check if payload appears unescaped
        if payload in response_text:
            return True
        # Check URL-decoded version
        from urllib.parse import unquote
        if unquote(payload) in unquote(response_text):
            return True
        return False

    def detect_error(self, response_text: str, error_patterns: list = None) -> str:
        """Detect database/application errors in response"""
        if error_patterns is None:
            error_patterns = [
                # MySQL/MariaDB (testphp.vulnweb.com and most PHP apps)
                r"SQL syntax", r"you have an error in your sql",
                r"check the manual that corresponds to your (mysql|mariadb)",
                r"mysql_fetch", r"mysql_num_rows", r"valid MySQL result",
                r"MySqlException", r"supplied argument is not a valid MySQL",
                # Oracle / PostgreSQL / MSSQL / SQLite
                r"ORA-[0-9]{4,5}", r"Oracle.*?error",
                r"PostgreSQL.*?(ERROR|error)", r"pg_query", r"pg_exec",
                r"Unclosed quotation", r"Microsoft OLE DB", r"ODBC.*?Driver",
                r"Incorrect syntax near", r"SQLite.*?(error|exception)",
                r"sqlite3.OperationalError", r"syntax error at or near",
                r"quoted string not properly terminated",
                # Generic app-level leaks
                r"Traceback \(most recent call last\)", r"Fatal error",
                r"Warning: ", r"stack trace:", r"Exception in thread",
            ]
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.I):
                return pattern
        return ""

    def detect_time_based(self, response_time: float, baseline: float = 0.5, threshold: float = 3.0) -> bool:
        """Detect time-based injection (response took significantly longer)"""
        return response_time > max(baseline * 3, threshold)

    def detect_file_content(self, response_text: str) -> str:
        """Detect if response contains file contents (path traversal success)"""
        markers = [
            ("root:", "/etc/passwd"), ("/bin/bash", "/etc/passwd"),
            ("[extensions]", "php.ini"), ("mysql_connect", "PHP config"),
            ("DB_CONNECTION", ".env file"),
        ]
        for marker, file_type in markers:
            if marker in response_text:
                return file_type
        return ""

    def close(self):
        self.session.close()


def normalize_url(url: str, timeout: int = 8) -> str:
    """Ensure a bare domain gets the RIGHT scheme. A missing scheme breaks requests
    (MissingSchema) and urlparse (hostname=None), silently killing all probing.

    Crucially, we don't just take whichever scheme 'responds' — many hosts answer on
    https with an empty parking/redirect page while the real app lives on http (e.g.
    testphp.vulnweb.com). So we fetch both and keep the one whose page actually carries
    links (a real application surface), which is what the whole scan depends on."""
    url = (url or "").strip()
    if not url or "://" in url:
        return url
    best, best_score = None, -1
    for scheme in ("https://", "http://"):
        candidate = scheme + url
        try:
            r = requests.get(candidate, timeout=timeout, allow_redirects=True, verify=False)
            # Score by discoverable links — an empty/parking page scores ~0.
            score = len(re.findall(r'(?:href|src|action)\s*=', r.text, re.I)) if r.status_code < 400 else 0
            if best is None:
                best = candidate  # first reachable scheme as fallback
            if score > best_score:
                best, best_score = candidate, score
        except Exception:
            continue
    return best or ("https://" + url)
