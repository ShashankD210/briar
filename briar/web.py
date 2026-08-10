"""Briar Web Dashboard — FastAPI, zero external deps, single source of truth."""
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse
import uvicorn, os, json, html, math
from datetime import datetime

try:
    import markdown as _markdown
except Exception:
    _markdown = None

from briar import __version__
from briar.agents import agents_for_mode, AGENT_ORDER, TOTAL_AGENTS, SCAN_MODES

app = FastAPI(title="Briar Dashboard")

SCANS_FILE = os.path.expanduser("~/.briar/scans.json")
WORKSPACES_DIR = os.path.expanduser("~/.briar/workspaces")
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_CLASS = {"Critical": "b-crit", "High": "b-high", "Medium": "b-med", "Low": "b-low", "Info": "b-info"}
SEV_COLOR = {"Critical": "#c084fc", "High": "#ff5470", "Medium": "#ff9f45", "Low": "#ffd43b", "Info": "#4dabf7"}
SEV_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
PROVIDERS = ["ollama", "openai", "anthropic", "deepseek", "groq", "mistral", "xai", "google", "openrouter", "together", "custom"]
MODE_LABELS = {"quick": "Quick", "standard": "Standard", "deep": "Deep"}
REPORT_LANGS = [("en", "English"), ("fr", "Français"), ("es", "Español"), ("de", "Deutsch"),
                ("it", "Italiano"), ("pt", "Português"), ("nl", "Nederlands"), ("ar", "العربية")]

CSS = """<style>
:root{
--ink:#0a0b10;--panel:#13151d;--raised:#1a1d27;
--line:rgba(255,255,255,.07);--lineHi:rgba(255,255,255,.15);
--fg:#e8e8f0;--muted:#8b8ea6;
--accent:#6d5efc;--accent2:#9a8cff;--red:#6d5efc;
--crit:#c084fc;--high:#ff5470;--med:#ff9f45;--low:#ffd43b;--info:#4dabf7;--ok:#51cf66;--warn:#ff9f45;
--glass:rgba(255,255,255,.025);--glassHover:rgba(255,255,255,.05);--border:var(--line);--borderHover:var(--lineHi);
--mono:ui-monospace,"JetBrains Mono","SF Mono","Cascadia Code",Menlo,Consolas,monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{color:var(--fg);font-family:var(--sans);line-height:1.6;min-height:100vh;-webkit-font-smoothing:antialiased;
background:radial-gradient(1200px 500px at 50% -200px,rgba(109,94,252,.10),transparent 70%),
linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px) 0 0/38px 38px,
linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px) 0 0/38px 38px,
var(--ink);background-attachment:fixed}
.header{background:rgba(10,11,16,.7);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--border);padding:16px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;position:sticky;top:0;z-index:10}
.header h1{font-size:17px;font-weight:800;color:var(--fg);letter-spacing:-.4px;display:flex;align-items:center;gap:10px}
.header h1::before{content:"";width:9px;height:18px;background:var(--accent);border-radius:2px;box-shadow:0 0 12px var(--accent);transform:skewX(-12deg)}
.header .sub{color:var(--muted);font-size:10.5px;font-weight:500;font-family:var(--mono);letter-spacing:.3px;margin-top:2px}
.nav-links{display:flex;gap:22px}
.nav-links a{color:var(--muted);text-decoration:none;font-size:11px;font-weight:700;font-family:var(--mono);text-transform:uppercase;letter-spacing:1px;padding:4px 0;border-bottom:2px solid transparent;transition:all .2s}
.nav-links a:hover,.nav-links a.active{color:var(--fg);border-bottom-color:var(--accent)}
.container{max-width:1200px;margin:0 auto;padding:28px 24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px 16px;position:relative;overflow:hidden;transition:border-color .2s,transform .2s}
.stat::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.5}
.stat:hover{border-color:var(--borderHover);transform:translateY(-2px)}
.stat .n{font-family:var(--mono);font-size:30px;font-weight:700;letter-spacing:-1px;line-height:1.1}
.stat .l{font-family:var(--mono);font-size:9.5px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;margin-top:8px;font-weight:600}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:22px;margin-bottom:16px;transition:border-color .2s}
.card:hover{border-color:var(--borderHover)}
.card h2{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--muted);margin-bottom:18px;letter-spacing:1px;text-transform:uppercase}
.card h2::before{content:"// ";color:var(--accent)}
.btn{background:rgba(109,94,252,.12);color:var(--accent2);border:1px solid rgba(109,94,252,.3);border-radius:8px;padding:8px 18px;font-size:12px;cursor:pointer;text-decoration:none;display:inline-block;font-weight:600;transition:all .2s;letter-spacing:-.2px}
.btn:hover{background:rgba(109,94,252,.22);border-color:rgba(109,94,252,.5);transform:translateY(-1px)}
.btn-sm{padding:5px 12px;font-size:11px;border-radius:6px}
.btn-green{background:rgba(81,207,102,.1);color:var(--ok);border-color:rgba(81,207,102,.25)}
.btn-green:hover{background:rgba(81,207,102,.18);border-color:rgba(81,207,102,.4)}
.btn-amber{background:rgba(255,159,69,.1);color:var(--med);border-color:rgba(255,159,69,.25)}
.btn-amber:hover{background:rgba(255,159,69,.18)}
table{width:100%;border-collapse:collapse}
th,td{padding:11px 16px;text-align:left;border-bottom:1px solid var(--border);font-size:13px}
th{color:var(--muted);text-transform:uppercase;font-size:9.5px;letter-spacing:1.5px;font-weight:700;font-family:var(--mono)}
tr:hover{background:var(--glassHover)}
.badge{display:inline-block;padding:3px 9px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;font-family:var(--mono)}
.b-crit{background:rgba(192,132,252,.15);color:var(--crit)}.b-high{background:rgba(255,84,112,.15);color:var(--high)}.b-med{background:rgba(255,159,69,.15);color:var(--med)}.b-low{background:rgba(255,212,59,.13);color:var(--low)}.b-info{background:rgba(77,171,247,.13);color:var(--info)}.b-ok{background:rgba(81,207,102,.14);color:var(--ok)}
form{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
input,select{background:var(--ink);border:1px solid var(--border);border-radius:9px;padding:10px 15px;color:var(--fg);font-size:13px;outline:none;font-family:inherit;transition:all .2s}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(109,94,252,.15)}
.empty{text-align:center;padding:48px;color:var(--muted)}.empty h3{font-size:16px;font-weight:700;margin-bottom:6px;color:var(--fg)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.search-box{flex:1;min-width:180px}
.sev-chip{background:var(--ink);color:var(--muted);border:1px solid var(--border);border-radius:7px;padding:5px 13px;font-size:11px;font-weight:700;font-family:var(--mono);cursor:pointer;transition:all .15s}
.sev-chip:hover{border-color:var(--borderHover);color:var(--fg)}
.sev-chip.active{background:rgba(109,94,252,.18);color:var(--accent2);border-color:rgba(109,94,252,.45)}
.copy-btn{background:var(--ink);color:var(--muted);border:1px solid var(--border);border-radius:5px;padding:1px 8px;font-size:10px;cursor:pointer;margin-left:6px;font-family:var(--mono)}
.copy-btn:hover{color:var(--accent2);border-color:var(--accent)}
.finding-row{display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid var(--border);font-size:13px;cursor:pointer;transition:all .15s}
.finding-row:hover{background:var(--glassHover);border-radius:8px;padding-left:8px;padding-right:8px}
.finding-detail{display:none;padding:16px;background:var(--ink);border-radius:10px;margin:8px 0;font-size:12px;overflow-y:auto;line-height:1.5;border:1px solid var(--border)}
.finding-detail.open{display:block}
.sev-dot{width:8px;height:8px;border-radius:2px;display:inline-block;flex-shrink:0}
.sev-bar{display:flex;height:6px;border-radius:3px;overflow:hidden;gap:2px;margin:6px 0 18px}
.sev-bar span{height:100%;border-radius:2px}
code{background:rgba(109,94,252,.12);padding:2px 6px;border-radius:4px;font-size:11px;color:var(--accent2);word-break:break-all;font-family:var(--mono)}
pre{background:var(--ink);border:1px solid var(--border);border-radius:10px;padding:12px;overflow-x:auto;color:var(--fg);font-size:11px;line-height:1.5;margin:8px 0;font-family:var(--mono)}
a{color:var(--accent2);text-decoration:none;transition:color .15s}a:hover{color:var(--fg)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.agent-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.agent-cell{display:flex;align-items:center;gap:7px;padding:9px 11px;border:1px solid var(--border);border-radius:8px;font-size:12px;background:var(--ink);font-family:var(--mono)}
.agent-cell.done{color:var(--ok);border-color:rgba(81,207,102,.3);background:rgba(81,207,102,.05)}
.agent-cell.pending{opacity:.4}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.live-dot{width:6px;height:6px;background:var(--high);border-radius:50%;display:inline-block;animation:pulse 1.4s infinite;margin-right:6px;box-shadow:0 0 8px var(--high)}
.progress-bar{position:relative;background:var(--ink);border:1px solid var(--border);border-radius:6px;height:8px;margin:8px 0 18px;overflow:hidden}
.progress-fill{background:linear-gradient(90deg,var(--accent),var(--accent2));height:100%;border-radius:6px;transition:width .5s ease}
@keyframes scan{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}
.scanline{position:absolute;top:0;bottom:0;width:25%;background:linear-gradient(90deg,transparent,rgba(154,140,255,.5),transparent);animation:scan 1.6s linear infinite}
.donut-wrap{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.legend{display:flex;flex-direction:column;gap:7px;min-width:150px}
.legend-item{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--fg)}
.legend-sw{width:10px;height:10px;border-radius:2px;flex-shrink:0}
.legend-item .lc{color:var(--muted);margin-left:auto;font-weight:600;font-family:var(--mono);font-size:11px}
.bar-row{display:flex;align-items:center;gap:10px;margin:8px 0;font-size:12px}
.bar-label{width:120px;color:var(--muted);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0;font-family:var(--mono);font-size:11px}
.bar-track{flex:1;background:var(--ink);border-radius:4px;height:15px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;min-width:2px;transition:width .6s ease}
.bar-val{width:30px;font-weight:700;color:var(--fg);font-family:var(--mono);font-size:12px}
.gauge{position:relative;width:132px;height:132px;flex-shrink:0;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--gc) calc(var(--sc)*3.6deg),rgba(255,255,255,.06) 0)}
.gauge::before{content:"";position:absolute;inset:9px;border-radius:50%;background:var(--panel)}
.gauge .g-inner{position:relative;text-align:center}
.gauge .gn{font-family:var(--mono);font-size:36px;font-weight:700;line-height:1;letter-spacing:-1px}
.gauge .gl{font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:1.5px;margin-top:6px;font-weight:700}
.summary{font-size:13.5px;line-height:1.7;color:var(--fg)}
.summary strong{color:var(--accent2)}
.chips-stack{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.tag{background:var(--ink);border:1px solid var(--border);border-radius:6px;padding:3px 9px;font-size:11px;color:var(--muted);font-family:var(--mono)}
.md-body{font-size:12.5px;line-height:1.65;color:var(--fg)}
.md-body h1,.md-body h2,.md-body h3,.md-body h4{color:var(--fg);margin:14px 0 6px;line-height:1.3;letter-spacing:-.2px}
.md-body h1{font-size:16px}.md-body h2{font-size:14px;color:var(--accent2)}.md-body h3{font-size:13px}.md-body h4{font-size:12.5px;color:var(--muted)}
.md-body p{margin:6px 0}.md-body ul,.md-body ol{margin:6px 0 6px 20px}.md-body li{margin:3px 0}
.md-body table{margin:8px 0}.md-body th,.md-body td{padding:6px 10px}
.md-body hr{border:none;border-top:1px solid var(--border);margin:12px 0}
@media(max-width:768px){.grid-2{grid-template-columns:1fr}.header{flex-direction:column;align-items:flex-start}.bar-label{width:84px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>"""

JS = """<script>
document.querySelectorAll('.finding-detail').forEach(el=>el.addEventListener('click',e=>e.stopPropagation()));
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.finding-detail.open').forEach(el=>el.classList.remove('open'))});
function filterSev(sev,btn){
  document.querySelectorAll('.sev-chip').forEach(c=>c.classList.remove('active'));
  if(btn)btn.classList.add('active');
  document.querySelectorAll('.finding-item').forEach(row=>{
    row.style.display=(sev==='all'||row.dataset.sev===sev)?'':'none';
  });
}
function searchFindings(q){
  q=q.toLowerCase();
  document.querySelectorAll('.finding-item').forEach(row=>{
    row.style.display=(row.dataset.text||'').includes(q)?'':'none';
  });
}
function copyText(btn){
  navigator.clipboard.writeText(btn.getAttribute('data-copy')||'').then(()=>{
    const o=btn.textContent;btn.textContent='copied';setTimeout(()=>btn.textContent=o,1200);
  });
}
</script>"""

REFRESH_5S = '<meta http-equiv="refresh" content="5">'


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def load_scans():
    return load_json(SCANS_FILE, [])


def save_scans(scans):
    os.makedirs(os.path.dirname(SCANS_FILE), exist_ok=True)
    with open(SCANS_FILE, "w") as f:
        json.dump(scans, f, indent=2)


def load_workspace_findings(name):
    return load_json(os.path.join(WORKSPACES_DIR, name, "findings.json"), []) if name else []


def load_workspace_state(name):
    return load_json(os.path.join(WORKSPACES_DIR, name, "state.json"), {}) if name else {}


def get_saved_provider():
    config_file = os.path.expanduser("~/.briar/config")
    try:
        with open(config_file) as f:
            for line in f:
                if line.startswith("PROVIDER="):
                    return line.strip().split("=", 1)[1]
    except Exception:
        pass
    return "ollama"


def get_saved_lang():
    try:
        with open(os.path.expanduser("~/.briar/config")) as f:
            for line in f:
                if line.startswith("REPORT_LANG="):
                    return line.strip().split("=", 1)[1].lower()
    except Exception:
        pass
    return "en"


def find_workspace(scan_id: str):
    for s in load_scans():
        if s.get("scan_id") == scan_id:
            ws = s.get("workspace")
            if ws and os.path.isdir(os.path.join(WORKSPACES_DIR, ws)):
                return ws
            break
    return None


def scan_record(scan_id: str):
    for s in load_scans():
        if s.get("scan_id") == scan_id:
            return s
    return {}


def report_exists(scan_id: str) -> dict:
    s = scan_record(scan_id)
    if not s:
        return {}
    out = os.path.expanduser(s.get("output_dir", "")) or os.path.join(os.getcwd(), "reports")
    result = {}
    if os.path.isdir(out):
        md = [f for f in os.listdir(out) if f.endswith('.md') and not f.startswith('.')]
        if md:
            result["markdown"] = sorted(md)[-1]
        if os.path.exists(os.path.join(out, "rapport.html")):
            result["html"] = "rapport.html"
        if os.path.isdir(os.path.join(out, "obsidian")):
            result["obsidian"] = "obsidian/"
    return result


def nav(active: str) -> str:
    items = [("/", "Scans"), ("/reports", "Reports"), ("/diff", "Diff"), ("/health", "API")]
    links = "".join(f'<a href="{h}" class="{"active" if h == active else ""}">{l}</a>' for h, l in items)
    return f'<div class="nav-links">{links}</div>'


def shell(title: str, header_inner: str, body: str, head_extra: str = "") -> str:
    return (f'<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1.0">'
            f'<title>{esc(title)}</title>{CSS}{head_extra}</head><body>'
            f'<div class="header">{header_inner}</div>'
            f'<div class="container">{body}</div>{JS}</body></html>')


def severity_counts(findings) -> dict:
    return {lvl: sum(1 for f in findings if f.get("severity") == lvl) for lvl in SEV_LEVELS}


import re as _re
_DANGER_TAGS = _re.compile(r'<\s*(script|iframe|object|embed|link|meta|base|form)\b[^>]*>.*?<\s*/\s*\1\s*>'
                           r'|<\s*(script|iframe|object|embed|link|meta|base|form)\b[^>]*/?>', _re.I | _re.S)
_ON_ATTR = _re.compile(r'\son\w+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)', _re.I)
_JS_URI = _re.compile(r'((?:href|src)\s*=\s*["\']?)\s*javascript:', _re.I)


def sanitize_html(rendered: str) -> str:
    """Neutralize XSS vectors in LLM-rendered analysis (scripts, iframes, inline
    event handlers, javascript: URIs) before it reaches the dashboard."""
    rendered = _DANGER_TAGS.sub('', rendered)
    rendered = _ON_ATTR.sub('', rendered)
    rendered = _JS_URI.sub(r'\1', rendered)
    return rendered


def md_to_html(text) -> str:
    text = str(text or "").strip()
    if not text:
        return '<p style="color:var(--muted)">No analysis.</p>'
    if _markdown is not None:
        try:
            return sanitize_html(_markdown.markdown(text, extensions=["fenced_code", "tables", "nl2br", "sane_lists"]))
        except Exception:
            pass
    return f"<pre>{esc(text)}</pre>"


def donut_svg(counts: dict, size: int = 190, stroke: int = 26) -> str:
    """Pure-SVG severity donut (camembert). No external deps."""
    segs_data = [(lvl, SEV_COLOR[lvl], counts.get(lvl, 0)) for lvl in SEV_LEVELS if counts.get(lvl, 0)]
    total = sum(c for _, _, c in segs_data)
    r = (size - stroke) / 2
    cx = cy = size / 2
    circ = 2 * math.pi * r
    if not total:
        return (f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="{stroke}"/>'
                f'<text x="{cx}" y="{cy+5}" text-anchor="middle" font-size="13" fill="#7a7a9a">no findings</text></svg>')
    segs, offset = "", 0.0
    for lvl, color, count in segs_data:
        seg = count / total * circ
        segs += (f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="{stroke}" '
                 f'stroke-dasharray="{seg:.3f} {circ - seg:.3f}" stroke-dashoffset="{-offset:.3f}" '
                 f'transform="rotate(-90 {cx} {cy})" stroke-linecap="butt"><title>{lvl}: {count}</title></circle>')
        offset += seg
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">{segs}'
            f'<text x="{cx}" y="{cy-4}" text-anchor="middle" font-size="36" font-weight="700" fill="#e8e8f0" font-family="ui-monospace,Menlo,monospace">{total}</text>'
            f'<text x="{cx}" y="{cy+18}" text-anchor="middle" font-size="9" letter-spacing="1.5" fill="#8b8ea6" font-family="ui-monospace,Menlo,monospace">FINDINGS</text></svg>')


def legend_html(counts: dict) -> str:
    total = sum(counts.values()) or 1
    rows = ""
    for lvl in SEV_LEVELS:
        c = counts.get(lvl, 0)
        if not c:
            continue
        rows += (f'<div class="legend-item"><span class="legend-sw" style="background:{SEV_COLOR[lvl]}"></span>'
                 f'{lvl}<span class="lc">{c} · {c / total * 100:.0f}%</span></div>')
    return f'<div class="legend">{rows}</div>' if rows else ''


def bars_html(pairs) -> str:
    """pairs = [(label, count, color)] sorted desc."""
    mx = max((c for _, c, _ in pairs), default=0)
    rows = ""
    for label, count, color in pairs:
        w = count / mx * 100 if mx else 0
        rows += (f'<div class="bar-row"><span class="bar-label" title="{esc(label)}">{esc(label)}</span>'
                 f'<div class="bar-track"><div class="bar-fill" style="width:{w:.1f}%;background:{color}"></div></div>'
                 f'<span class="bar-val">{count}</span></div>')
    return rows or '<p style="color:var(--muted);font-size:12px">No data.</p>'


SEV_WEIGHT = {"Critical": 30, "High": 12, "Medium": 4, "Low": 1, "Info": 0}


def risk_score(findings) -> tuple:
    """Confidence-weighted risk: (score 0-100, label, color). Unconfirmed findings
    count a quarter, so a report never screams 'High' off unproven heuristics."""
    score = 0.0
    for f in findings:
        w = SEV_WEIGHT.get(f.get("severity"), 0)
        score += w if f.get("confirmed") else w * 0.25
    # A confirmed high-severity finding sets a floor (1 proven SQLi is not "Medium").
    if any(f.get("confirmed") and f.get("severity") == "Critical" for f in findings):
        score = max(score, 90)
    elif any(f.get("confirmed") and f.get("severity") == "High" for f in findings):
        score = max(score, 60)
    score = min(100, int(round(score)))
    confirmed = any(f.get("confirmed") for f in findings)
    if score >= 70:
        label = "Critical"
    elif score >= 40:
        label = "High"
    elif score >= 15:
        label = "Medium"
    elif score > 0:
        label = "Low"
    else:
        return 0, "Clean", SEV_COLOR["Info"]
    if not confirmed:
        label += " (unverified)"
    base = label.split()[0]
    return score, label, SEV_COLOR.get(base, SEV_COLOR["Info"])


@app.get("/", response_class=HTMLResponse)
async def home():
    scans = load_scans()
    scans_sorted = sorted(scans, key=lambda s: s.get("date", ""), reverse=True)
    total_findings = sum(s.get("findings", 0) for s in scans)
    running = sum(1 for s in scans if s.get("status") == "running")
    saved = get_saved_provider()

    # Aggregate severity across all scans (for the global donut)
    agg = {lvl: 0 for lvl in SEV_LEVELS}
    for s in scans:
        for f in load_workspace_findings(s.get("workspace")):
            sev = f.get("severity", "Info")
            if sev in agg:
                agg[sev] += 1
    # Most vulnerable targets (cheap: from scan records)
    top_targets = sorted(((s.get("target", "?"), s.get("findings", 0)) for s in scans if s.get("findings")),
                         key=lambda x: -x[1])[:8]
    target_pairs = [[t.replace("https://", "").replace("http://", "")[:28], c, "var(--accent)"] for t, c in top_targets]

    prov_opts = "".join(f'<option value="{p}" {"selected" if p == saved else ""}>{p}</option>' for p in PROVIDERS)
    mode_opts = "".join(
        f'<option value="{m}" {"selected" if m == "standard" else ""}>{MODE_LABELS[m]} ({len(agents_for_mode(m))})</option>'
        for m in ("quick", "standard", "deep"))
    saved_lang = get_saved_lang()
    lang_opts = "".join(f'<option value="{c}" {"selected" if c == saved_lang else ""}>{n}</option>'
                        for c, n in REPORT_LANGS)

    rows = ""
    for s in scans_sorted[:30]:
        sid = esc(s.get("scan_id", s.get("date", "")))
        status = s.get("status", "?")
        if status == "done":
            badge = '<span class="badge b-info">Done</span>'
        elif status == "running":
            badge = '<span class="badge b-high"><span class="live-dot"></span>Running</span>'
        else:
            badge = f'<span class="badge b-low">{esc(status)}</span>'
        rows += f"""<tr>
            <td style="color:var(--muted);font-size:11px;white-space:nowrap">{esc(s.get('date','?'))}</td>
            <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{esc(s.get('target','?'))}">{esc(s.get('target','?'))}</td>
            <td><span class="badge b-info">{esc(s.get('mode','?'))}</span></td>
            <td>{s.get('findings',0)}</td>
            <td>{badge}</td>
            <td style="white-space:nowrap">
                <a href="/scan/{sid}" class="btn btn-sm btn-green">Detail</a>
                <a href="/scan/{sid}/live" class="btn btn-sm btn-amber">Live</a>
            </td>
        </tr>"""
    if not scans_sorted:
        rows = '<tr><td colspan="6"><div class="empty"><h3>No scans yet</h3><p>Launch your first scan above.</p></div></td></tr>'

    header = (f'<div><h1>Briar Dashboard</h1><p class="sub">Autonomous AI Pentester · v{__version__}</p></div>{nav("/")}')
    body = f"""<div class="stats">
<div class="stat"><div class="n">{len(scans)}</div><div class="l">Scans</div></div>
<div class="stat"><div class="n">{total_findings}</div><div class="l">Findings</div></div>
<div class="stat"><div class="n" style="color:var(--high)">{running}</div><div class="l">Running</div></div>
<div class="stat"><div class="n">{TOTAL_AGENTS}</div><div class="l">Agents</div></div>
<div class="stat"><div class="n">{len(PROVIDERS)}</div><div class="l">Providers</div></div>
</div>
<div class="grid-2">
<div class="card"><h2>Severity Across All Scans</h2><div class="donut-wrap">{donut_svg(agg)}{legend_html(agg)}</div></div>
<div class="card"><h2>Most Findings by Target</h2>{bars_html(target_pairs)}</div>
</div>
<div class="card"><h2>New Scan</h2>
<form action="/scan" method="get">
<input type="url" name="url" placeholder="https://target.com" required style="flex:1;min-width:200px">
<select name="provider">{prov_opts}</select>
<select name="mode">{mode_opts}</select>
<select name="lang" title="Report language">{lang_opts}</select>
<button type="submit" class="btn">Launch</button>
</form></div>
<div class="card"><h2>Scan History</h2><table><tr><th>Date</th><th>Target</th><th>Mode</th><th>Findings</th><th>Status</th><th></th></tr>{rows}</table></div>"""
    return HTMLResponse(shell("Briar Dashboard", header, body))


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(scan_id: str):
    ws_name = find_workspace(scan_id)
    findings = load_workspace_findings(ws_name)
    findings_sorted = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "Info"), 99))
    counts = severity_counts(findings_sorted)
    total = len(findings_sorted)
    confirmed = sum(1 for f in findings_sorted if f.get("confirmed"))
    rec = scan_record(scan_id)
    target_url = rec.get("target", "")
    risk_n, risk_l, risk_c = risk_score(findings_sorted)

    # Findings grouped by agent (bar chart), colored by each agent's worst severity
    agent_count, agent_worst = {}, {}
    for f in findings_sorted:
        a, sev = f.get("agent", "?"), f.get("severity", "Info")
        agent_count[a] = agent_count.get(a, 0) + 1
        if a not in agent_worst or SEV_ORDER.get(sev, 99) < SEV_ORDER.get(agent_worst[a], 99):
            agent_worst[a] = sev
    agent_pairs = sorted(
        ([a, c, SEV_COLOR.get(agent_worst.get(a, "Info"), "#89b4fa")] for a, c in agent_count.items()),
        key=lambda x: -x[1])[:14]

    # Detected stack (from recon)
    recon = next((f for f in findings if f.get("agent") == "Recon"), {})
    stack = ([recon["server"]] if recon.get("server") else []) + (recon.get("technologies") or [])
    tags = "".join(f'<span class="tag">{esc(t)}</span>' for t in stack[:12])
    tags_html = f'<div class="chips-stack">{tags}</div>' if tags else ''

    # Executive summary
    if total:
        sev_phrase = ", ".join(f"{counts[l]} {l.lower()}" for l in SEV_LEVELS if counts[l])
        summary = (f"This scan surfaced <strong>{total} finding(s)</strong> ({sev_phrase}). "
                   f"Overall risk is <strong style=\"color:{risk_c}\">{risk_l}</strong>.")
        if confirmed:
            summary += f' <strong>{confirmed}</strong> were actively confirmed.'
    else:
        summary = "No findings surfaced. The target looks clean for the agents that ran."

    reports = report_exists(scan_id)
    report_links = ""
    if reports.get("html"):
        report_links += f'<a href="/report/{esc(scan_id)}" class="btn btn-sm">Full Report</a> '
    if reports.get("obsidian"):
        report_links += f'<span class="btn btn-sm" style="opacity:.5">Obsidian: {esc(reports["obsidian"])}</span> '

    chips = f'<button class="sev-chip active" onclick="filterSev(\'all\',this)">All ({total})</button>'
    for lvl in SEV_LEVELS:
        if counts[lvl]:
            chips += f'<button class="sev-chip" onclick="filterSev(\'{lvl}\',this)">{lvl} ({counts[lvl]})</button>'

    findings_html = ""
    for f in findings_sorted:
        sev = f.get("severity", "Info")
        ftype, agent = esc(f.get("type", "?")), esc(f.get("agent", "?"))
        url_f, param = esc(f.get("url", "?")), esc(f.get("param", ""))
        payload, poc = esc(f.get("payload", "")), esc(f.get("poc", ""))
        analysis = md_to_html(f.get("analysis", f.get("raw", "")))
        blob = esc(f"{f.get('type','')} {f.get('agent','')} {f.get('url','')} {f.get('param','')}".lower())
        conf = ('<span class="badge b-ok">Confirmed</span>' if f.get("confirmed")
                else '<span class="badge b-low">Unconfirmed</span>')
        cscore = f.get("confidence")
        cbadge = (f'<span class="badge b-info" title="Confidence {cscore}%">{esc(f.get("confidence_label", ""))} {cscore}%</span>'
                  if cscore is not None else '')
        review = ('<p><span class="badge b-med">Needs review</span> flagged High/Critical not proven by evidence.</p>'
                  if f.get("needs_review") else '')
        payload_html = (f'<p><strong>Payload:</strong> <code>{payload}</code>'
                        f'<button class="copy-btn" data-copy="{payload}" onclick="copyText(this)">copy</button></p>') if payload else ''
        poc_html = (f'<p><strong>PoC:</strong> <button class="copy-btn" data-copy="{poc}" onclick="copyText(this)">copy</button></p><pre>{poc}</pre>') if poc else ''
        findings_html += f"""<div class="finding-item" data-sev="{sev}" data-text="{blob}">
<div class="finding-row" onclick="this.nextElementSibling.classList.toggle('open')">
<span class="sev-dot" style="background:{SEV_COLOR.get(sev,'#666')}"></span>
<span class="badge {SEV_CLASS.get(sev,'b-info')}">{sev}</span>
<span style="flex:1;font-weight:500">{ftype}</span>
{cbadge}
<span style="color:var(--muted);font-size:10px">{agent}</span>
<span style="color:var(--muted);font-size:14px">&#9662;</span></div>
<div class="finding-detail">
<p><strong>Endpoint:</strong> <code>{url_f}</code></p>
{f'<p><strong>Param:</strong> <code>{param}</code></p>' if param else ''}
{payload_html}
<p>{conf}</p>
{review}
{poc_html}
<hr style="border-color:var(--border);margin:8px 0">
<div class="md-body">{analysis}</div></div></div>"""
    if not findings_sorted:
        findings_html = '<div class="empty"><h3>No findings</h3><p>This scan produced no results.</p></div>'

    header = (f'<div><h1><a href="/" style="color:var(--red)">Briar</a> / Report</h1>'
              f'<p class="sub">{esc(target_url)}</p></div>'
              f'<div style="display:flex;gap:8px;flex-wrap:wrap">{report_links}'
              f'<a href="/report/{esc(scan_id)}/expert.pdf" class="btn btn-sm">Expert PDF</a>'
              f'<a href="/export/{esc(scan_id)}" class="btn btn-sm">Export JSON</a>'
              f'<a href="/scan/{esc(scan_id)}/live" class="btn btn-sm btn-amber">Live</a>'
              f'<a href="/stop/{esc(scan_id)}" class="btn btn-sm" style="color:var(--high);border-color:var(--high)">Stop</a>'
              f'<a href="/" class="btn btn-sm">Back</a></div>')
    body = f"""<div class="stats">
<div class="stat"><div class="n">{total}</div><div class="l">Total</div></div>
<div class="stat"><div class="n" style="color:var(--crit)">{counts['Critical']}</div><div class="l">Critical</div></div>
<div class="stat"><div class="n" style="color:var(--high)">{counts['High']}</div><div class="l">High</div></div>
<div class="stat"><div class="n" style="color:var(--med)">{counts['Medium']}</div><div class="l">Medium</div></div>
<div class="stat"><div class="n" style="color:var(--low)">{counts['Low']}</div><div class="l">Low</div></div>
<div class="stat"><div class="n" style="color:var(--ok)">{confirmed}</div><div class="l">Confirmed</div></div>
</div>
<div class="grid-2">
<div class="card"><h2>Severity Breakdown</h2><div class="donut-wrap">{donut_svg(counts)}{legend_html(counts)}</div></div>
<div class="card"><h2>Risk Summary</h2>
<div style="display:flex;gap:18px;align-items:center">
<div class="gauge" style="--sc:{risk_n};--gc:{risk_c}"><div class="g-inner"><div class="gn" style="color:{risk_c}">{risk_n}</div><div class="gl" style="color:{risk_c}">{risk_l} risk</div></div></div>
<div class="summary">{summary}{tags_html}</div></div></div>
</div>
<div class="card"><h2>Findings by Agent</h2>{bars_html(agent_pairs)}</div>
<div class="card"><h2>Findings &amp; Full Analysis ({total})</h2>
<div class="toolbar">{chips}<input class="search-box" type="text" placeholder="Search findings..." oninput="searchFindings(this.value)"></div>
{findings_html}</div>"""
    return HTMLResponse(shell(f"Report {scan_id}", header, body))


@app.get("/scan/{scan_id}/live", response_class=HTMLResponse)
async def scan_live(scan_id: str):
    ws_name = find_workspace(scan_id)
    findings = load_workspace_findings(ws_name)
    state = load_workspace_state(ws_name)
    rec = scan_record(scan_id)
    mode = state.get("mode") or rec.get("mode", "standard")
    agents = agents_for_mode(mode)
    done = state.get("agents_completed", [])
    target = state.get("target", "?")
    if target == "?":
        target = rec.get("target", "?")
    is_running = rec.get("status") == "running"
    pct = min(100, len(done) / max(1, len(agents)) * 100)
    scanline = '<div class="scanline"></div>' if is_running else ''

    cells = ""
    for a in agents:
        is_done = a in done
        cls = "done" if is_done else "pending"
        mark = "&#10003;" if is_done else "&#9679;"
        cells += f'<div class="agent-cell {cls}">{mark} {esc(a)}</div>'

    latest = "".join(
        f'<div class="finding-row"><span class="sev-dot" style="background:{SEV_COLOR.get(f.get("severity","Info"),"#666")}"></span>'
        f'<span class="badge {SEV_CLASS.get(f.get("severity","Info"),"b-info")}">{f.get("severity","?")}</span>'
        f'<span style="flex:1;font-size:12px">{esc(f.get("type","?"))}</span></div>'
        for f in findings[-8:]) or '<div class="empty" style="padding:20px"><p>Waiting for findings...</p></div>'

    header = (f'<div><h1><a href="/" style="color:var(--red)">Briar</a> / Live</h1>'
              f'<p class="sub">{esc(target)} {"<span class=\"live-dot\" style=\"margin-left:8px\"></span>Running" if is_running else "- Done"}</p></div>'
              f'<a href="/scan/{esc(scan_id)}" class="btn btn-sm">Detail</a>')
    body = f"""<div class="stats">
<div class="stat"><div class="n">{len(findings)}</div><div class="l">Findings</div></div>
<div class="stat"><div class="n">{len(done)}/{len(agents)}</div><div class="l">Agents</div></div>
<div class="stat"><div class="n">{int(pct)}%</div><div class="l">Progress</div></div>
</div>
<div class="progress-bar">{scanline}<div class="progress-fill" style="width:{pct}%"></div></div>
<div class="grid-2">
<div class="card"><h2>Agents ({len(done)}/{len(agents)})</h2><div class="agent-grid">{cells}</div></div>
<div class="card"><h2>Latest Findings ({len(findings)})</h2>{latest}</div>
</div>"""
    return HTMLResponse(shell("Live - Briar", header, body, head_extra=(REFRESH_5S if is_running else "")))


@app.get("/reports", response_class=HTMLResponse)
async def reports_page():
    scans_sorted = sorted(load_scans(), key=lambda s: s.get("date", ""), reverse=True)
    rows = ""
    for s in scans_sorted[:30]:
        if s.get("status") != "done":
            continue
        sid = esc(s.get("scan_id", ""))
        avail = report_exists(s.get("scan_id", ""))
        html_link = (f'<a href="/report/{sid}" class="btn btn-sm btn-green">HTML</a>'
                     if avail.get("html") else '<span style="color:var(--muted);font-size:10px">--</span>')
        rows += f"""<tr>
            <td style="color:var(--muted);font-size:11px">{esc(s.get('date','?'))}</td>
            <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(s.get('target','?'))}</td>
            <td>{s.get('findings',0)}</td>
            <td style="white-space:nowrap">{html_link} <a href="/scan/{sid}" class="btn btn-sm">Detail</a></td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="4"><div class="empty"><h3>No reports</h3><p>Completed scans will appear here.</p></div></td></tr>'
    header = f'<div><h1><a href="/" style="color:var(--red)">Briar</a> / Reports</h1></div>{nav("/reports")}'
    body = f'<div class="card"><h2>Completed Scans</h2><table><tr><th>Date</th><th>Target</th><th>Findings</th><th>Reports</th></tr>{rows}</table></div>'
    return HTMLResponse(shell("Reports - Briar", header, body))


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def view_report(scan_id: str):
    out = os.path.expanduser(scan_record(scan_id).get("output_dir", ""))
    if out and os.path.isdir(out):
        html_path = os.path.join(out, "rapport.html")
        if os.path.exists(html_path):
            with open(html_path) as f:
                return HTMLResponse(f.read())
    return HTMLResponse(shell("No report", '<div><h1>Briar / Report</h1></div>',
                              '<div class="empty"><h3>No HTML report found</h3><p>Run a scan that generates a report.</p></div>'))


@app.get("/scan")
async def launch_scan(url: str, provider: str = None, mode: str = "standard", lang: str = None,
                      background_tasks: BackgroundTasks = None):
    provider = provider or get_saved_provider()
    from briar.core.http import normalize_url
    url = normalize_url(url)
    if mode not in SCAN_MODES:
        mode = "standard"
    lang = (lang or get_saved_lang() or "en").lower()
    if lang not in {c for c, _ in REPORT_LANGS}:
        lang = "en"
    scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
    from briar.core.workspace import Workspace
    ws = Workspace(url, mode)
    out_dir = os.path.expanduser(f"~/.briar/reports/{ws.name}")
    scans = load_scans()
    scans.append({"scan_id": scan_id, "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                  "target": url, "provider": provider, "mode": mode, "lang": lang, "status": "running",
                  "findings": 0, "workspace": ws.name, "output_dir": out_dir})
    save_scans(scans)

    def run_scan():
        os.environ.setdefault("BRIAR_HTTP_TIMEOUT", "6")
        os.environ["BRIAR_REPORT_LANG"] = lang
        # Load saved API keys so paid providers work from the dashboard (not just ollama)
        try:
            with open(os.path.expanduser("~/.briar/config")) as _f:
                for _line in _f:
                    if "=" in _line:
                        _k, _v = _line.strip().split("=", 1)
                        if _k.endswith("_API_KEY") or _k.startswith(("OLLAMA_", "CUSTOM_")):
                            os.environ[_k] = _v
        except Exception:
            pass
        from briar.agents import run_scan_agents, filter_noise
        # Agents run concurrently (recon first), checkpointing live for the dashboard
        findings = run_scan_agents(
            agents_for_mode(mode), provider, url, lang=lang,
            on_result=lambda n, r: ws.checkpoint_agent(n, [r] if r and "error" not in r else []))
        # Drop noise, then confirm High/Critical by replaying the exploit
        findings, _ = filter_noise(findings)
        try:
            from briar.core.validator import ExploitValidator
            findings = ExploitValidator().validate_all(findings, url)
        except Exception:
            pass
        try:
            from briar.core.confidence import apply_confidence
            findings = apply_confidence(findings)
        except Exception:
            pass
        # Persist the clean, validated set so the dashboard reflects it
        try:
            fpath = os.path.join(WORKSPACES_DIR, ws.name, "findings.json")
            with open(fpath, "w") as f:
                json.dump(findings, f, indent=2)
        except Exception:
            pass
        try:
            from briar.reports.generator import ReportGenerator
            from briar.reports.obsidian import ObsidianGenerator
            if findings:
                ReportGenerator(url, findings, out_dir).all_formats()
                ObsidianGenerator(url, findings, f"{out_dir}/obsidian").generate()
        except Exception:
            pass
        scans = load_scans()
        for s in scans:
            if s.get("scan_id") == scan_id:
                s["status"] = "done"
                s["findings"] = len(findings)
                break
        save_scans(scans)

    if background_tasks:
        background_tasks.add_task(run_scan)
    return RedirectResponse(url="/", status_code=303)


@app.get("/stop/{scan_id}")
async def stop_scan(scan_id: str):
    scans = load_scans()
    for s in scans:
        if s.get("scan_id") == scan_id and s.get("status") == "running":
            s["status"] = "stopped"
            break
    save_scans(scans)
    return RedirectResponse(url="/", status_code=303)


@app.get("/report/{scan_id}/expert.pdf")
async def expert_report(scan_id: str):
    rec = scan_record(scan_id)
    findings = load_workspace_findings(find_workspace(scan_id))
    out = os.path.expanduser(rec.get("output_dir", "")) or os.path.join(os.getcwd(), "reports")
    meta = {"scanner": "Briar", "version": __version__, "mode": rec.get("mode", "?"),
            "provider": rec.get("provider", "?"), "lang": rec.get("lang", "en")}
    try:
        from briar.reports.expert import ExpertReport
        res = ExpertReport(rec.get("target", ""), findings, out, meta).generate()
    except Exception:
        res = {}
    if res.get("pdf") and os.path.exists(res["pdf"]):
        return FileResponse(res["pdf"], media_type="application/pdf",
                            filename=f"briar_report_{scan_id}.pdf")
    if res.get("html") and os.path.exists(res["html"]):
        with open(res["html"]) as f:
            return HTMLResponse(f.read())
    return HTMLResponse(shell("Expert Report", '<div><h1>Briar / Expert Report</h1></div>',
                              '<div class="empty"><h3>Could not generate the report</h3><p>The scan may have no findings yet.</p></div>'))


@app.get("/export/{scan_id}")
async def export_scan(scan_id: str):
    rec = scan_record(scan_id)
    findings = load_workspace_findings(find_workspace(scan_id))
    payload = {"scan": rec, "findings": findings, "count": len(findings),
               "exported": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    return Response(content=json.dumps(payload, indent=2, ensure_ascii=False),
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="briar_{scan_id}.json"'})


@app.get("/diff", response_class=HTMLResponse)
async def diff_view(a: str = "", b: str = ""):
    scans = sorted([s for s in load_scans() if s.get("scan_id")], key=lambda s: s.get("date", ""), reverse=True)

    def options(sel):
        return "".join(
            f'<option value="{esc(s["scan_id"])}" {"selected" if s["scan_id"] == sel else ""}>'
            f'{esc(s.get("date", "?"))} — {esc(s.get("target", "?"))[:38]}</option>' for s in scans)

    diff_html = ""
    if a and b:
        wa, wb = find_workspace(a), find_workspace(b)
        if wa and wb:
            from briar.core.diff import diff_workspaces
            d = diff_workspaces(wa, wb)
            sm = d["summary"]

            def section(title, items, color, changed=False):
                if not items:
                    return ""
                rows = ""
                for i in items:
                    sev = i.get("severity", "Info")
                    extra = (f'<span style="color:var(--muted);font-size:10px">was {esc(i.get("old_severity", "?"))}</span>'
                             if changed else f'<span style="color:var(--muted);font-size:10px">{esc(i.get("agent", "?"))}</span>')
                    rows += (f'<div class="finding-row" style="cursor:default">'
                             f'<span class="sev-dot" style="background:{SEV_COLOR.get(sev, "#666")}"></span>'
                             f'<span class="badge {SEV_CLASS.get(sev, "b-info")}">{sev}</span>'
                             f'<span style="flex:1">{esc(i.get("type", "?"))}</span>{extra}</div>')
                return f'<div class="card"><h2 style="color:{color}">{title} ({len(items)})</h2>{rows}</div>'

            diff_html = f"""<div class="stats">
<div class="stat"><div class="n" style="color:var(--high)">{sm['new_findings']}</div><div class="l">New</div></div>
<div class="stat"><div class="n" style="color:var(--ok)">{sm['fixed_findings']}</div><div class="l">Fixed</div></div>
<div class="stat"><div class="n" style="color:var(--med)">{sm['changed_severity']}</div><div class="l">Changed</div></div>
<div class="stat"><div class="n">{sm['unchanged']}</div><div class="l">Unchanged</div></div>
</div>
{section("New findings", d["new"], "var(--high)")}
{section("Severity changed", d["changed"], "var(--med)", changed=True)}
{section("Fixed", d["fixed"], "var(--ok)")}"""
        else:
            diff_html = '<div class="empty"><h3>Pick two scans</h3><p>Both scans need a saved workspace to compare.</p></div>'

    header = f'<div><h1><a href="/" style="color:var(--red)">Briar</a> / Diff</h1></div>{nav("/diff")}'
    form = (f'<div class="card"><h2>Compare Two Scans</h2>'
            f'<form action="/diff" method="get">'
            f'<select name="a">{options(a)}</select>'
            f'<span style="color:var(--muted);align-self:center">against</span>'
            f'<select name="b">{options(b)}</select>'
            f'<button class="btn" type="submit">Compare</button></form></div>')
    return HTMLResponse(shell("Diff - Briar", header, form + diff_html))


@app.get("/health")
async def health():
    return {"status": "ok", "version": __version__, "agents": TOTAL_AGENTS,
            "providers": len(PROVIDERS), "scans": len(load_scans())}


def main():
    host = os.environ.get("BRIAR_HOST", "127.0.0.1")
    port = int(os.environ.get("BRIAR_PORT", "8233"))
    print(f"Briar Dashboard -> http://{host}:{port}  (set BRIAR_HOST=0.0.0.0 for LAN access)")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
