# Briar — Claude Code Agent Instructions

## CRUCIAL — Read this first

- **Owner**: Stiimy (JOBLON Keran, keran.joblon@outlook.fr, @Stiimrael_bot Telegram)
- **Repo**: https://github.com/Stiimy/briar (public)
- **PyPI**: `briar-pentest` (v0.4.37, package name ≠ module name)
- **License**: AGPL-3.0
- **Python**: 3.14 on Arch Linux (PEP 668 enforced — always use `--break-system-packages` with pip)
- **Secrets**: NEVER hardcode here (repo is public). Stored in `~/.briar/config` (chmod 600, KEY=VALUE per line):
  - `DEEPSEEK_API_KEY` — DeepSeek API key (also readable as env `$DEEPSEEK_API_KEY`)
  - `PYPI_TOKEN` — PyPI upload token for `briar-pentest`
  - Load them: `set -a; . ~/.briar/config; set +a` (or read the single key you need)

## Architecture (32 agents)

> Roster + tiers are defined ONCE in `briar/agents/__init__.py` (`AGENT_ORDER` + `SCAN_MODES`). cli.py / web.py / worker.py all consume `agents_for_mode(mode)` — never hardcode the list/count again.

```
briar/
├── agents/        Analyzer (LLM brain) + 31 scan agents:
│                  Recon, Headers, Secrets, InfoDisclosure, Injection, XSS, SSRF, CVE,
│                  Auth, AuthZ, IDOR, RCE, Traversal, CSRF, AdminPanel, BackupFiles,
│                  Planner, GitBackup, NoSQL, SSTI, XXE, CRLF, Upload, Session, JWT,
│                  CORS, OpenRedirect, HostHeader, GraphQL, Cache, API, Nuclei
│  core/          + crawler.py (spider/attack-surface), confidence.py (evidence scoring)
│  reports/       + expert.py (expertise-grade HTML+PDF via chromium headless)
│  Report language: --lang / dashboard dropdown / REPORT_LANG (en fr es de it pt nl ar)
├── providers/     11 backends: Ollama(free), OpenAI, Anthropic, DeepSeek, Groq,
│                  Mistral, xAI/Grok, Google/Gemini, OpenRouter, Together, Custom
├── core/          http.py (shared HTTP), params.py (80+ attack params),
│                  validator.py (replay exploits), workspace.py (checkpoint/resume),
│                  animation.py (Sylph ASCII), diff.py (scan comparison)
├── exploits/      browser.py (Selenium XSS/SQLi) + CLI injector
├── reports/       generator.py (MD/Word/Excel), obsidian.py (Karpathy LLM-Wiki),
│                  html_report.py (Claude-style interactive report)
├── charts/        generator.py (donut, heatmap, bar — matplotlib dark theme)
├── slides/        pptx_gen.py (PPTX + HTML)
├── cli.py         Main entry (click + rich, 16 agent scan flow)
├── web.py         FastAPI dashboard (:8233, glassmorphism, pure Python HTML)
├── worker.py      Background job queue (file-based)
└── config.py      YAML config loader (auth, rules, login flows)
```

## Commit style STRICT

**ALL COMMITS MUST USE LoL/Briar-themed names.** No version numbers. No descriptions.

Examples:
- `Needlessly Large Rod` (fix)
- `Level 16 Powerspike` (feature)
- `Dark Harvest` (rune/ability)
- `BotRK` (item abbreviation)
- `Doran Blade` (starting item)
- `Not lazy for that one ;)` (Stiimy's style)

**Bump 3rd digit only** (0.4.x → 0.4.x+1), never the major/minor.

## Publish flow

```bash
sed -i 's/0.4.XX/0.4.YY/g' pyproject.toml setup.py briar/__init__.py briar/cli.py briar/web.py
git add -A && git commit -m "Item Name"
git push --force  # history is rewritten often
rm -rf dist/ && python3 -m build
. ~/.briar/config
TWINE_USERNAME=__token__ TWINE_PASSWORD="$PYPI_TOKEN" python3 -m twine upload dist/*
```

## Key gotchas

- Never edit `cli.py` with sed — use Python for edits (sed breaks indentation)
- Never edit `web.py` with string replacement — indentation WILL break
- Matplotlib needs `matplotlib.use('Agg')` before any import (headless)
- The dashboard's CSS is inline in `web.py` CSS variable — no external files
- Filter-branch renames commit history — always force push after
- `briar-pentest` is the PyPI name, but the module is `briar`
- Agent count: 32 for `--deep`, 16 for standard, 8 for quick (source: `SCAN_MODES` in `agents/__init__.py`). Nuclei is deep-only (slow).
- Expert PDF needs chromium flags: `--headless=new --disable-dev-shm-usage --user-data-dir=<temp> --virtual-time-budget=N` + a CSP `default-src 'none'` in the HTML (else chromium hangs on remote resources in LLM analysis)
- Don't add "Error" or noisy "Info" findings to reports
- Ollama is NOT the default — user must run `briar setup` first

## Testing

```bash
python -m briar                          # banner
python -m briar status                   # show config
python -m briar scan -u https://httpbin.org --quick   # reads key from ~/.briar/config
pkill -f briar.web; python -m briar serve  # dashboard on :8233
```

## Stiimy's preferences

- NO emojis in new code or dashboard (he hates them)
- Clean, minimal design (Vercel/Railway glassmorphism)
- French is fine for conversation, code in English
- Commits: anime/gaming/LoL references only
- Don't touch README content without asking
- Obsidian is his main report viewer — reports go there
- He hates default Ollama — always use saved config
- Dashboard must show real data, not hardcoded defaults
