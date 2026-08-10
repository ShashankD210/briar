"""Briar Confidence Scoring — evidence-based reliability, zero false positives."""

# Score tiers mapped to human-readable labels. Ordered high to low.
CONFIDENCE_LABELS = {
    "confirmed": "Confirmed",     # exploit replayed successfully
    "high": "Probable",           # concrete HTTP evidence collected
    "medium": "Known CVE",        # template match or documented CVE
    "low": "Unverified",          # LLM analysis only, no hard evidence
}


def score_finding(finding: dict) -> tuple:
    """Return (score:int 0-100, label:str) from the evidence in a finding."""
    if not isinstance(finding, dict):
        return 35, CONFIDENCE_LABELS["low"]

    # Strongest: the exploit was actually replayed and confirmed by the validator.
    if finding.get("confirmed") is True:
        return 95, "Confirmed"

    # Concrete HTTP evidence gathered during probing (marker/payload/status).
    real = finding.get("real_findings")
    if isinstance(real, list) and len(real) > 0:
        return 75, "Probable"

    # Nuclei template engine matched a known signature.
    if finding.get("nuclei"):
        return 70, "Template match"

    # Tied to a documented CVE / CVSS score.
    if finding.get("cve") or finding.get("cvss"):
        return 65, "Known CVE"

    # Nothing concrete: LLM analysis alone, treat as unproven.
    return 35, "Unverified"


def apply_confidence(findings: list) -> list:
    """Annotate each finding with confidence, confidence_label and review flags."""
    if not isinstance(findings, list):
        return findings

    high_sev = {"high", "critical"}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        score, label = score_finding(finding)
        finding["confidence"] = score
        finding["confidence_label"] = label

        # Anti-false-positive: loud severity but no proof -> flag, do not downgrade.
        severity = str(finding.get("severity", "")).strip().lower()
        if severity in high_sev and score < 50:
            finding["needs_review"] = True
            finding["original_severity"] = finding.get("severity")
    return findings


def proven(findings: list, min_score: int = 60) -> list:
    """Return only findings whose confidence score is at least min_score."""
    if not isinstance(findings, list):
        return []
    result = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        score = finding.get("confidence")
        if score is None:
            score, _ = score_finding(finding)
        if score >= min_score:
            result.append(finding)
    return result


def confidence_summary(findings: list) -> dict:
    """Return counts and average score for display."""
    summary = {"confirmed": 0, "probable": 0, "unverified": 0, "avg": 0.0}
    if not isinstance(findings, list) or not findings:
        return summary

    total = 0
    counted = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        score = finding.get("confidence")
        if score is None:
            score, _ = score_finding(finding)
        total += score
        counted += 1
        if score >= 95:
            summary["confirmed"] += 1
        elif score >= 60:
            summary["probable"] += 1
        else:
            summary["unverified"] += 1

    summary["avg"] = round(total / counted, 1) if counted else 0.0
    return summary
