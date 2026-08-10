"""Briar Attack Params — shared parameter lists for all agents 🎯"""
from urllib.parse import urlparse, parse_qs


def params_from_url(url: str) -> list:
    """Real query-string parameter names present in a URL (the actually-attackable
    params, e.g. 'cat' in /listproducts.php?cat=1). Empty list if none/parse fails."""
    try:
        return list(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []


def merge_params(url: str, defaults: list, cap: int = 10) -> list:
    """URL's own params first (most likely vulnerable), then generic defaults, deduped."""
    out, seen = [], set()
    for p in params_from_url(url) + list(defaults):
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out[:cap]



INJECTION = [
    "q", "id", "page", "search", "query", "user", "email",
    "name", "file", "path", "dir", "document", "src",
    "url", "redirect", "callback", "next", "return",
    "token", "key", "hash", "slug", "category", "type",
    "sort", "order", "filter", "data", "input", "value",
    "text", "content", "param", "action", "cmd", "exec",
]

XSS = [
    "q", "search", "query", "name", "message", "comment",
    "text", "content", "title", "description", "bio",
    "feedback", "review", "body", "subject", "about",
]

SSRF = [
    "url", "redirect", "callback", "next", "return",
    "goto", "link", "uri", "path", "dest", "target",
    "proxy", "forward", "fetch", "download", "source",
]

TRAVERSAL = [
    "file", "path", "dir", "document", "src", "template",
    "include", "page", "folder", "download", "load",
    "read", "view", "open", "get", "show",
]

CSRF_CHECK = [
    "csrf", "token", "nonce", "_token", "authenticity_token",
    "xsrf", "_csrf", "csrf_token",
]

AUTH = [
    "username", "password", "email", "login", "signin",
    "user", "pass", "pwd", "auth", "token", "session",
]

RCE_CMD = [
    "cmd", "exec", "command", "run", "ip", "host", "ping",
    "name", "q", "search", "action", "do", "shell",
]
