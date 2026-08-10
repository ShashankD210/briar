"""Crawler / Spider — attack surface discovery via BFS

Discovers URLs, endpoints, forms and parameters on the same domain.
Supports optional authenticated crawling to reach post-login surface.
Bridges the gap with Burp Suite's crawler.
"""
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs

from bs4 import BeautifulSoup

from briar.core.http import HTTPClient

# Extensions we list but never follow (not HTML documents).
SKIP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".css", ".js", ".mp3", ".mp4", ".avi", ".mov", ".woff", ".woff2",
    ".ttf", ".eot", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)

# Hints that a URL is a distinct endpoint / API surface.
API_HINTS = ("/api/", "/graphql", "/rest/", ".php", ".json", ".xml", ".asp", ".aspx", ".jsp", ".do")


class Crawler:
    """BFS spider that maps a target's attack surface"""

    def __init__(self, timeout=10, max_pages=40, max_depth=2, same_domain=True):
        self.http = HTTPClient(timeout=timeout)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.same_domain = same_domain

    def login(self, login_url, credentials: dict, method="form"):
        """Authenticate to populate the session cookie.

        POSTs credentials (form-encoded or JSON) via the shared HTTPClient so
        subsequent crawl requests reuse the authenticated session. Returns True
        on an apparent success (non-error status), False otherwise.
        """
        try:
            if str(method).lower() == "json":
                resp = self.http.post(login_url, json=credentials)
            else:
                resp = self.http.post(login_url, data=credentials)
            return resp.status_code < 400
        except Exception:
            return False

    def _is_followable(self, url):
        """A link worth fetching for further discovery (HTML-ish, no fragment)."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        path = parsed.path.lower()
        if path.endswith(SKIP_EXTENSIONS):
            return False
        return True

    @staticmethod
    def _is_endpoint(url):
        """URL that carries a query string or looks like an API/dynamic path."""
        parsed = urlparse(url)
        if parsed.query:
            return True
        lowered = url.lower()
        return any(hint in lowered for hint in API_HINTS)

    def _extract(self, base_url, html):
        """Pull links, forms, scripts and params out of one page."""
        links = set()
        forms = []
        params = set()

        soup = BeautifulSoup(html, "lxml")

        # <a href> and generic navigational links.
        for tag in soup.find_all("a", href=True):
            absolute = urljoin(base_url, tag["href"].strip())
            clean, _ = urldefrag(absolute)
            if clean:
                links.add(clean)

        # <script src> — listed as discovered URLs (not followed for HTML).
        for tag in soup.find_all("script", src=True):
            absolute = urljoin(base_url, tag["src"].strip())
            clean, _ = urldefrag(absolute)
            if clean:
                links.add(clean)

        # <form> action / method / input names.
        for form in soup.find_all("form"):
            action = urljoin(base_url, (form.get("action") or "").strip())
            clean_action, _ = urldefrag(action or base_url)
            method = (form.get("method") or "GET").strip().upper()
            inputs = []
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if name:
                    inputs.append(name)
                    params.add(name)
            forms.append({
                "action": clean_action or base_url,
                "method": method,
                "inputs": inputs,
            })
            if clean_action:
                links.add(clean_action)

        # Query-string params from every discovered link.
        for link in links:
            for key in parse_qs(urlparse(link).query).keys():
                params.add(key)

        return links, forms, params

    def crawl(self, base_url: str, auth: dict = None) -> dict:
        """BFS the target starting from base_url.

        If auth is provided (auth={"login_url":..., "credentials":{...}, "method":...})
        authenticate first so the crawl covers the post-login surface.
        """
        if auth:
            self.login(
                auth.get("login_url"),
                auth.get("credentials", {}),
                auth.get("method", "form"),
            )

        base_domain = urlparse(base_url).netloc

        clean_base, _ = urldefrag(base_url)
        seen = {clean_base}
        visited_urls = []
        discovered = set()
        endpoints = set()
        forms = []
        form_signatures = set()
        params = set()
        external_links = 0

        queue = deque([(clean_base, 0)])
        fetch_errors = []

        while queue and len(visited_urls) < self.max_pages:
            url, depth = queue.popleft()

            try:
                resp = self.http.get(url)
            except Exception as e:
                if len(fetch_errors) < 3:
                    fetch_errors.append(f"{url}: {type(e).__name__}: {e}")
                continue

            visited_urls.append(url)
            discovered.add(url)
            if self._is_endpoint(url):
                endpoints.add(url)

            # Only parse HTML bodies for further links.
            content_type = resp.headers.get("Content-Type", "").lower()
            if "html" not in content_type and content_type:
                continue

            try:
                links, page_forms, page_params = self._extract(url, resp.text)
            except Exception:
                continue

            params.update(page_params)

            for form in page_forms:
                signature = (
                    form["action"],
                    form["method"],
                    tuple(sorted(form["inputs"])),
                )
                if signature not in form_signatures:
                    form_signatures.add(signature)
                    forms.append(form)

            for link in links:
                discovered.add(link)
                if self._is_endpoint(link):
                    endpoints.add(link)

                link_domain = urlparse(link).netloc
                is_same = link_domain == base_domain
                if not is_same:
                    external_links += 1
                    if self.same_domain:
                        continue

                if link in seen:
                    continue
                seen.add(link)

                if depth + 1 > self.max_depth:
                    continue
                if not self._is_followable(link):
                    continue
                if len(seen) > self.max_pages * 4:
                    continue
                queue.append((link, depth + 1))

        return {
            "base": base_url,
            "pages_crawled": len(visited_urls),
            "urls": sorted(discovered),
            "endpoints": sorted(endpoints),
            "forms": forms,
            "params": sorted(params),
            "external_links": external_links,
            "errors": fetch_errors,
        }
