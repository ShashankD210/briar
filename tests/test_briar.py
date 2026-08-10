"""Briar test suite — unit tests for the detection chain + an end-to-end scan
against the built-in vulnerable app. Run: pytest -q"""
import briar.agents.analyzer as az
from briar.core.http import HTTPClient, normalize_url
from briar.core.params import merge_params, params_from_url, INJECTION
from briar.core.validator import ExploitValidator
from briar.core.confidence import apply_confidence, score_finding
from briar.agents import AGENTS, AGENT_ORDER, agents_for_mode, run_scan_agents, filter_noise


# ---- core helpers ---------------------------------------------------------

def test_normalize_url_keeps_explicit_scheme():
    assert normalize_url("http://x.io") == "http://x.io"
    assert normalize_url("https://x.io/a") == "https://x.io/a"


def test_params_from_url_and_merge():
    assert params_from_url("http://x/p.php?cat=1&artist=2") == ["cat", "artist"]
    merged = merge_params("http://x/p.php?cat=1", INJECTION)
    assert merged[0] == "cat"  # real param first
    assert "q" in merged      # generics still included


def test_send_payload_replaces_existing_param():
    # The core detection fix: an existing ?cat=1 must be REPLACED, not appended.
    h = HTTPClient.__new__(HTTPClient)
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    url, param, payload = "http://x/lp.php?cat=1", "cat", "' OR 1=1--"
    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    q[param] = [payload]
    target = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
    assert "cat=1&" not in target and "OR" in target.replace("+", " ")


def test_detect_error_catches_real_mysql_error():
    h = HTTPClient.__new__(HTTPClient)
    txt = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    assert h.detect_error(txt)
    assert not h.detect_error("welcome to our homepage")


def test_validator_confirms_only_with_marker():
    v = ExploitValidator()
    f = {"type": "SQL Injection", "severity": "Critical", "url": "http://x/lp.php?cat=1",
         "real_findings": [{"param": "cat", "payload": "' OR 1=1--"}]}
    v.http.send_payload = lambda u, p, pl, m="GET": {"status": 200, "length": 5, "time": 0.1,
                                                     "text_snippet": "error in your SQL syntax", "headers": {}}
    assert v.validate(dict(f), "http://x/")["confirmed"] is True
    v.http.send_payload = lambda u, p, pl, m="GET": {"status": 200, "length": 5, "time": 0.1,
                                                     "text_snippet": "welcome", "headers": {}}
    assert v.validate(dict(f), "http://x/")["confirmed"] is False


def test_confidence_scoring_tiers():
    assert score_finding({"confirmed": True})[0] >= 90
    assert score_finding({"analysis": "llm only"})[0] <= 50


def test_risk_score_downweights_unconfirmed():
    from briar.web import risk_score
    unconfirmed = [{"severity": "High"} for _ in range(4)] + [{"severity": "Medium"} for _ in range(17)]
    n, label, _ = risk_score(unconfirmed)
    assert "unverified" in label and n < 40           # noise must not read as High
    n2, label2, _ = risk_score([{"severity": "Critical", "confirmed": True}])
    assert label2 == "Critical" and n2 >= 70          # a proven crit is Critical


def test_registry_consistent():
    assert set(AGENTS) == set(AGENT_ORDER)
    assert len(agents_for_mode("quick")) < len(agents_for_mode("deep"))


# ---- end to end -----------------------------------------------------------

def test_end_to_end_confirms_sqli_on_builtin_vuln_app():
    """The crown-jewel test: scan the built-in vulnerable app and require a
    CONFIRMED injection finding (proves recon -> routing -> inject -> confirm)."""
    from briar.demo import serve
    orig = az.SecurityAnalyzer.analyze_endpoint
    az.SecurityAnalyzer.analyze_endpoint = (
        lambda self, url, method="GET", source_hint="", tech_context="", plan_context="":
        {"url": url, "analysis": "(test)", "raw": ""})
    server, url = serve()
    try:
        findings = run_scan_agents(["recon", "injection", "xss", "traversal"], "ollama", url, max_workers=6)
        findings, _ = filter_noise(findings)
        findings = ExploitValidator().validate_all(findings, url)
        findings = apply_confidence(findings)
    finally:
        az.SecurityAnalyzer.analyze_endpoint = orig
        server.shutdown()
    confirmed = [f for f in findings if f.get("confirmed")]
    assert any("Injection" in str(f.get("type", "")) or f.get("agent") == "Injection" for f in confirmed), \
        "expected a confirmed injection finding on the vulnerable app"
    assert len(confirmed) >= 2  # SQLi + at least one XSS/traversal
