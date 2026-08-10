"""Briar Expert Report — print-optimized A4 PDF via chromium headless"""
import os
import html
import subprocess
import shutil
from datetime import datetime

try:
    import markdown as _markdown
except Exception:  # pragma: no cover - markdown may be unavailable
    _markdown = None


# Severity metadata: order weight, risk score weight, badge color (white-bg safe)
SEVERITY_META = {
    "Critical": {"order": 0, "weight": 30, "color": "#b31d5f"},
    "High":     {"order": 1, "weight": 12, "color": "#d12f4a"},
    "Medium":   {"order": 2, "weight": 4,  "color": "#c77d18"},
    "Low":      {"order": 3, "weight": 1,  "color": "#b59a00"},
    "Info":     {"order": 4, "weight": 0,  "color": "#2b6cb0"},
}
DEFAULT_SEV = {"order": 5, "weight": 0, "color": "#6b7280"}


class ExpertReport:
    def __init__(self, target: str, findings: list, output_dir: str = "./reports", meta: dict = None):
        self.target = target
        self.findings = findings or []
        self.output_dir = output_dir
        self.meta = meta or {}
        self.generated_at = datetime.now()
        self.report_id = "BRIAR-" + self.generated_at.strftime("%Y%m%d-%H%M%S")

    # ---- helpers ----------------------------------------------------------

    def _sev_meta(self, severity: str) -> dict:
        return SEVERITY_META.get(severity, DEFAULT_SEV)

    def _severity_counts(self) -> dict:
        counts = {k: 0 for k in SEVERITY_META}
        for f in self.findings:
            sev = f.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
            else:
                counts.setdefault("Other", 0)
                counts["Other"] += 1
        return counts

    def _risk_score(self, counts: dict) -> int:
        score = 0
        for sev, meta in SEVERITY_META.items():
            score += counts.get(sev, 0) * meta["weight"]
        return min(score, 100)

    def _verdict(self, counts: dict) -> str:
        if counts.get("Critical", 0) > 0:
            return "Critical"
        if counts.get("High", 0) > 0:
            return "High"
        if counts.get("Medium", 0) > 0:
            return "Medium"
        if counts.get("Low", 0) > 0:
            return "Low"
        return "Clean"

    def _sorted_findings(self) -> list:
        return sorted(
            self.findings,
            key=lambda f: self._sev_meta(f.get("severity", "Info"))["order"],
        )

    def _render_markdown(self, text: str) -> str:
        if not text:
            return ""
        if _markdown is not None:
            try:
                return _markdown.markdown(
                    text, extensions=["fenced_code", "tables", "nl2br"]
                )
            except Exception:
                pass
        # Fallback: escape and keep line breaks
        return "<p>" + html.escape(str(text)).replace("\n", "<br>") + "</p>"

    # ---- style ------------------------------------------------------------

    def _css(self) -> str:
        return """
@page { size: A4; margin: 18mm; }
* { box-sizing: border-box; }
html, body {
    background: #ffffff;
    color: #1a1a1a;
    font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.5;
    margin: 0;
    padding: 0;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
}
h1, h2, h3, h4 { color: #111827; font-weight: 700; line-height: 1.25; }
h1 { font-size: 26pt; margin: 0 0 8px; }
h2 { font-size: 16pt; margin: 26px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #111827; }
h3 { font-size: 12.5pt; margin: 0 0 6px; }
p { margin: 0 0 10px; }
a { color: #2b6cb0; text-decoration: none; }
code, pre { font-family: "SF Mono", "Consolas", "Menlo", monospace; }
pre {
    background: #f6f7f9;
    border: 1px solid #d9dde3;
    border-radius: 5px;
    padding: 10px 12px;
    font-size: 9.5pt;
    line-height: 1.4;
    white-space: pre-wrap;
    word-break: break-word;
    overflow-wrap: anywhere;
    margin: 8px 0;
}
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 10.5pt; }
th, td { border: 1px solid #cbd2da; padding: 6px 10px; text-align: left; vertical-align: top; }
th { background: #f2f4f7; font-weight: 600; }

/* Cover */
.cover {
    page-break-after: always;
    min-height: 235mm;
    display: flex;
    flex-direction: column;
    justify-content: center;
}
.cover .kicker { font-size: 11pt; letter-spacing: 2px; text-transform: uppercase; color: #6b7280; margin-bottom: 6px; }
.cover .target { font-size: 14pt; color: #374151; margin: 6px 0 24px; word-break: break-all; }
.cover .meta-grid { display: table; width: 100%; margin-top: 20px; border-top: 1px solid #d9dde3; }
.cover .meta-row { display: table-row; }
.cover .meta-row > div { display: table-cell; padding: 8px 0; border-bottom: 1px solid #eceff3; font-size: 10.5pt; }
.cover .meta-row .k { color: #6b7280; width: 40%; }
.cover .meta-row .v { color: #111827; font-weight: 600; }

/* Badges */
.badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 4px;
    color: #ffffff;
    font-size: 9pt;
    font-weight: 700;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    vertical-align: middle;
}
.badge-confirmed {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 4px;
    background: #1f7a44;
    color: #ffffff;
    font-size: 9pt;
    font-weight: 700;
    text-transform: uppercase;
    vertical-align: middle;
}

/* Risk bar */
.riskbar-track { background: #eceff3; border-radius: 6px; height: 20px; width: 100%; overflow: hidden; border: 1px solid #d9dde3; }
.riskbar-fill { height: 100%; }
.score-line { font-size: 20pt; font-weight: 700; margin: 4px 0; }
.verdict-tag { display: inline-block; padding: 3px 12px; border-radius: 4px; color: #fff; font-weight: 700; font-size: 11pt; }

/* Severity distribution bar */
.dist-bar { display: flex; width: 100%; height: 22px; border-radius: 5px; overflow: hidden; border: 1px solid #d9dde3; margin: 8px 0; }
.dist-seg { height: 100%; }

/* Findings */
.finding {
    page-break-inside: avoid;
    border: 1px solid #d9dde3;
    border-left-width: 5px;
    border-radius: 6px;
    padding: 14px 16px;
    margin: 0 0 16px;
}
.finding-head { display: flex; align-items: baseline; justify-content: space-between; gap: 10px; margin-bottom: 8px; }
.finding-head .fid { color: #6b7280; font-size: 10pt; font-weight: 700; letter-spacing: 1px; }
.finding-title { font-size: 12.5pt; font-weight: 700; color: #111827; margin: 0; }
.finding-meta { font-size: 10pt; color: #374151; margin: 6px 0; }
.finding-meta .label { color: #6b7280; }
.kv { margin: 4px 0; }
.analysis { margin-top: 10px; border-top: 1px solid #eceff3; padding-top: 10px; }
.analysis h1, .analysis h2, .analysis h3, .analysis h4 { border: none; font-size: 11.5pt; margin: 12px 0 4px; padding: 0; }
.analysis pre { background: #f6f7f9; }

.footer-note { color: #6b7280; font-size: 9.5pt; }
.disclaimer { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 12px 16px; font-size: 10pt; color: #374151; }
.signature { margin-top: 24px; page-break-inside: avoid; }
.signature .sig-space { border-top: 1px solid #9ca3af; width: 55%; margin-top: 40px; padding-top: 4px; color: #6b7280; font-size: 9.5pt; }
.muted { color: #6b7280; }
"""

    # ---- sections ---------------------------------------------------------

    def _cover_html(self) -> str:
        e = html.escape
        scanner = e(str(self.meta.get("scanner", "Briar")))
        version = e(str(self.meta.get("version", "")))
        rows = [
            ("Target", e(self.target)),
            ("Report ID", e(self.report_id)),
            ("Generated", e(self.generated_at.strftime("%Y-%m-%d %H:%M:%S"))),
            ("Scanner", (scanner + " " + version).strip()),
        ]
        if self.meta.get("mode"):
            rows.append(("Assessment Mode", e(str(self.meta.get("mode")))))
        if self.meta.get("provider"):
            rows.append(("LLM Provider", e(str(self.meta.get("provider")))))
        rows.append(("Total Findings", str(len(self.findings))))

        meta_rows = "".join(
            '<div class="meta-row"><div class="k">{}</div><div class="v">{}</div></div>'.format(k, v)
            for k, v in rows
        )
        return """
<section class="cover">
    <div class="kicker">Confidential Security Assessment</div>
    <h1>Security Assessment Report</h1>
    <div class="target">{target}</div>
    <div class="meta-grid">{rows}</div>
    <p class="footer-note" style="margin-top:auto; padding-top:30px;">
        This document is generated by an automated assessment engine. Distribution restricted.
    </p>
</section>
""".format(target=e(self.target), rows=meta_rows)

    def _summary_html(self, counts: dict, score: int, verdict: str) -> str:
        # Severity table
        table_rows = ""
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            meta = SEVERITY_META[sev]
            table_rows += (
                '<tr><td><span class="badge" style="background:{c}">{s}</span></td>'
                '<td>{n}</td></tr>'
            ).format(c=meta["color"], s=sev, n=counts.get(sev, 0))
        if counts.get("Other"):
            table_rows += (
                '<tr><td><span class="badge" style="background:{c}">Other</span></td>'
                '<td>{n}</td></tr>'
            ).format(c=DEFAULT_SEV["color"], n=counts["Other"])

        # Distribution bar (proportional segments)
        total = max(len(self.findings), 1)
        segs = ""
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            n = counts.get(sev, 0)
            if n <= 0:
                continue
            pct = (n / total) * 100
            segs += '<div class="dist-seg" style="width:{p:.2f}%;background:{c}" title="{s}: {n}"></div>'.format(
                p=pct, c=SEVERITY_META[sev]["color"], s=sev, n=n
            )
        if not segs:
            segs = '<div class="dist-seg" style="width:100%;background:#eceff3"></div>'

        verdict_color = self._sev_meta(verdict)["color"] if verdict != "Clean" else "#1f7a44"

        return """
<section>
    <h2>Executive Summary</h2>
    <p>An autonomous security assessment was performed against the target. A total of
    <strong>{total}</strong> observation(s) were recorded across all assessment agents.
    The findings below are prioritized by severity to support efficient remediation.</p>

    <div style="display:flex; gap:24px; align-items:flex-start; flex-wrap:wrap;">
        <div style="flex:1; min-width:220px;">
            <table>
                <thead><tr><th>Severity</th><th>Count</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        <div style="flex:1; min-width:220px;">
            <div class="label muted" style="font-size:10pt;">Global Risk Score</div>
            <div class="score-line">{score}<span class="muted" style="font-size:12pt;"> / 100</span></div>
            <div class="riskbar-track"><div class="riskbar-fill" style="width:{score}%;background:{vc}"></div></div>
            <div style="margin-top:12px;">
                <span class="muted" style="font-size:10pt;">Verdict:</span>
                <span class="verdict-tag" style="background:{vc}">{verdict}</span>
            </div>
        </div>
    </div>

    <div class="label muted" style="font-size:10pt; margin-top:14px;">Severity Distribution</div>
    <div class="dist-bar">{segs}</div>
</section>
""".format(total=len(self.findings), rows=table_rows, score=score, vc=verdict_color,
           verdict=html.escape(verdict), segs=segs)

    def _methodology_html(self) -> str:
        agents = sorted({str(f.get("agent", "Unknown")) for f in self.findings})
        agents_html = "".join("<li>{}</li>".format(html.escape(a)) for a in agents) or "<li>None</li>"
        return """
<section>
    <h2>Methodology</h2>
    <p>The assessment follows a layered, autonomous workflow. Reconnaissance profiles the target
    surface (headers, technologies, endpoints, exposed ports). A multi-agent scanning phase then
    probes for common and context-specific weaknesses. Candidate issues pass through an exploit
    validation stage that attempts safe confirmation to reduce false positives. Confirmed and
    high-signal results are consolidated by a reporting template engine into this document.</p>
    <p class="label muted" style="font-size:10pt;">Assessment agents that produced findings:</p>
    <ul>{agents}</ul>
</section>
""".format(agents=agents_html)

    def _finding_html(self, index: int, f: dict) -> str:
        e = html.escape
        sev = f.get("severity", "Info")
        meta = self._sev_meta(sev)
        fid = "F-{:02d}".format(index)
        ftype = e(str(f.get("type", f.get("agent", "Finding"))))

        parts = []
        parts.append('<div class="finding" style="border-left-color:{c}">'.format(c=meta["color"]))
        parts.append('<div class="finding-head">')
        parts.append('<div><span class="fid">{fid}</span> &nbsp;<span class="finding-title">{t}</span></div>'.format(fid=fid, t=ftype))
        parts.append('<div><span class="badge" style="background:{c}">{s}</span></div>'.format(c=meta["color"], s=e(str(sev))))
        parts.append('</div>')  # finding-head

        # Meta line
        meta_bits = []
        meta_bits.append('<span class="label">Agent:</span> {}'.format(e(str(f.get("agent", "Unknown")))))
        if f.get("cve"):
            meta_bits.append('<span class="label">CVE:</span> {}'.format(e(str(f.get("cve")))))
        if f.get("cvss") not in (None, ""):
            meta_bits.append('<span class="label">CVSS:</span> {}'.format(e(str(f.get("cvss")))))
        if f.get("confidence") not in (None, "") or f.get("confidence_label"):
            conf = f.get("confidence_label") or f.get("confidence")
            meta_bits.append('<span class="label">Confidence:</span> {}'.format(e(str(conf))))
        if f.get("confirmed"):
            meta_bits.append('<span class="badge-confirmed">Confirmed</span>')
        parts.append('<div class="finding-meta">' + " &nbsp;|&nbsp; ".join(meta_bits) + '</div>')

        # Endpoint
        if f.get("url"):
            parts.append('<div class="kv finding-meta"><span class="label">Endpoint:</span> <code>{}</code></div>'.format(e(str(f.get("url")))))

        # Payload / PoC
        if f.get("payload"):
            parts.append('<div class="kv finding-meta"><span class="label">Payload</span></div>')
            parts.append('<pre>{}</pre>'.format(e(str(f.get("payload")))))
        if f.get("poc"):
            parts.append('<div class="kv finding-meta"><span class="label">Proof of Concept</span></div>')
            parts.append('<pre>{}</pre>'.format(e(str(f.get("poc")))))

        # real_findings (optional structured evidence)
        rf = f.get("real_findings")
        if rf:
            if isinstance(rf, (list, tuple)):
                rf_text = "\n".join(str(x) for x in rf)
            else:
                rf_text = str(rf)
            parts.append('<div class="kv finding-meta"><span class="label">Evidence</span></div>')
            parts.append('<pre>{}</pre>'.format(e(rf_text)))

        # Analysis (markdown -> HTML, NOT escaped)
        analysis = f.get("analysis")
        if analysis:
            parts.append('<div class="analysis">{}</div>'.format(self._render_markdown(str(analysis))))

        parts.append('</div>')  # finding
        return "".join(parts)

    def _findings_html(self) -> str:
        ordered = self._sorted_findings()
        if not ordered:
            return '<section><h2>Findings Detail</h2><p class="muted">No findings were recorded.</p></section>'
        body = "".join(self._finding_html(i + 1, f) for i, f in enumerate(ordered))
        return '<section><h2>Findings Detail</h2>{}</section>'.format(body)

    def _disclaimer_html(self) -> str:
        return """
<section>
    <h2>Disclaimer</h2>
    <div class="disclaimer">
        <p>This report was produced by an automated security assessment engine. Its contents are
        provided for informational purposes and must be reviewed and validated by a qualified
        security professional before any action is taken. Automated analysis can produce false
        positives and may not capture every relevant issue; absence of a finding is not a guarantee
        of security.</p>
        <p>The assessment was intended to be conducted only against systems for which the operator
        holds explicit authorization. Any use of this document or the underlying tooling against
        systems without such authorization is strictly prohibited and may be unlawful.</p>
    </div>
</section>
"""

    def _signature_html(self) -> str:
        e = html.escape
        scanner = e(str(self.meta.get("scanner", "Briar")))
        version = e(str(self.meta.get("version", "")))
        return """
<section class="signature">
    <h2>Report Authenticity</h2>
    <p class="footer-note">Generated by {scanner} {version} on {date} — Report ID {rid}</p>
    <div class="sig-space">Reviewed by (signature / date)</div>
</section>
""".format(scanner=scanner, version=version,
           date=e(self.generated_at.strftime("%Y-%m-%d %H:%M:%S")), rid=e(self.report_id))

    # ---- public API -------------------------------------------------------

    def html(self) -> str:
        counts = self._severity_counts()
        score = self._risk_score(counts)
        verdict = self._verdict(counts)
        body = (
            self._cover_html()
            + self._summary_html(counts, score, verdict)
            + self._methodology_html()
            + self._findings_html()
            + self._disclaimer_html()
            + self._signature_html()
        )
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report — {title}</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>""".format(title=html.escape(self.report_id), css=self._css(), body=body)

    def generate(self) -> dict:
        result = {"html": None, "pdf": None}
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            html_path = os.path.abspath(os.path.join(self.output_dir, "report_expert.html"))
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(self.html())
            result["html"] = html_path
        except Exception:
            return result

        # PDF conversion via chromium headless — best-effort, bounded, never hangs.
        # The report HTML ships a strict CSP (default-src 'none') so chromium never
        # waits on remote resources embedded in LLM analysis (a past hang cause).
        try:
            import tempfile
            chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("chrome")
            if not chromium:
                return result
            pdf_path = os.path.abspath(os.path.join(self.output_dir, "report_expert.pdf"))
            profile = tempfile.mkdtemp(prefix="briar_chrome_")
            cmd = [
                chromium, "--headless=new", "--no-sandbox", "--disable-gpu",
                "--disable-dev-shm-usage", "--user-data-dir=" + profile, "--no-first-run",
                "--virtual-time-budget=10000", "--no-pdf-header-footer",
                "--print-to-pdf=" + pdf_path, "file://" + html_path,
            ]
            try:
                subprocess.run(cmd, timeout=45, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            finally:
                shutil.rmtree(profile, ignore_errors=True)
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                result["pdf"] = pdf_path
        except Exception:
            pass

        return result
