# Briar — Agent Instructions

## Project
Briar is an autonomous AI pentester. Python 3.10+, AGPL-3.0. Published on PyPI as `briar-pentest`.

## Architecture
```
briar/
├── agents/        33 security agents
├── providers/     11 AI backends (Ollama free, OpenAI, Claude, DeepSeek...)
├── core/          http.py, params.py, validator.py, workspace.py, animation.py, diff.py
├── exploits/      browser.py (Selenium) + CLI injector
├── reports/       generator.py, obsidian.py (LLM-Wiki), html_report.py
├── charts/        generator.py (donut, heatmap, bar)
├── cli.py         Main CLI (click + rich), web.py (FastAPI dashboard :8233)
└── config.py      YAML config loader
```

## Commit style
- All commits use LoL/Briar-themed names (items, runes, abilities)
- Only bump 3rd version digit (0.4.x -> 0.4.x+1)
- Push with --force after filter-branch (history is rewritten)

## Key gotchas
- Matplotlib needs `matplotlib.use('Agg')` before import (headless)
- Dashboard CSS is inline in web.py — no external files
- Agent count is 33 for `--deep`, 8 for standard, 4 for quick
- No hardcoded defaults — user must run `briar setup`

## Publish flow
```bash
sed -i 's/0.4.XX/0.4.YY/g' pyproject.toml setup.py briar/__init__.py briar/cli.py briar/web.py
git add -A && git commit -m "Item Name" && git push
rm -rf dist/ && python3 -m build
twine upload --skip-existing dist/*
```
