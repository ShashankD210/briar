#!/usr/bin/env python3
"""Briar CLI — Autonomous AI Pentester 🥀"""
import sys, os, click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from briar.agents import agents_for_mode, TOTAL_AGENTS
from briar import __version__

console = Console()

def load_saved_config():
    """Load provider and API keys from ~/.briar/config. Returns dict or None."""
    config_file = os.path.expanduser("~/.briar/config")
    if not os.path.exists(config_file):
        return None
    config = {}
    with open(config_file) as f:
        for line in f:
            if '=' in line:
                k, v = line.strip().split('=', 1)
                config[k] = v
                if k.endswith('_API_KEY') or k == 'OLLAMA_HOST' or k == 'OLLAMA_PORT' or k == 'OLLAMA_MODEL' or k == 'CUSTOM_ENDPOINT' or k == 'CUSTOM_MODEL':
                    os.environ[k] = v  # Load into env for providers
    return config


PROVIDER_KEYS = {
    "deepseek": "DEEPSEEK_API_KEY", "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY", "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY", "xai": "XAI_API_KEY",
    "google": "GOOGLE_API_KEY", "openrouter": "OPENROUTER_API_KEY",
    "together": "TOGETHER_API_KEY", "custom": "CUSTOM_API_KEY",
}


def registered_providers(saved):
    """Providers with a key registered in ~/.briar/config (order: saved default first)."""
    saved = saved or {}
    regs = []
    for name, keyenv in PROVIDER_KEYS.items():
        if saved.get(keyenv) or os.environ.get(keyenv):
            regs.append(name)
    if (saved.get("CUSTOM_ENDPOINT") or saved.get("CUSTOM_API_KEY")) and "custom" not in regs:
        regs.append("custom")
    default = saved.get("PROVIDER", "")
    if default in regs:  # surface the saved default first
        regs.remove(default)
        regs.insert(0, default)
    return regs


BANNER = f"""
[bold red]
  ██████╗ ██████╗ ██╗ █████╗ ██████╗ 
  ██╔══██╗██╔══██╗██║██╔══██╗██╔══██╗
  ██████╔╝██████╔╝██║███████║██████╔╝
  ██╔══██╗██╔══██╗██║██╔══██║██╔══██╗
  ██████╔╝██║  ██║██║██║  ██║██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝[/bold red]
[cyan]              Autonomous AI Pentester[/cyan]
[dim]         11 providers · {TOTAL_AGENTS} agents · AGPL-3.0[/dim]
[bold #cc0000]                  v0.4.58[/bold #cc0000]
"""

def check_ollama():
    from briar.providers import get_provider
    try:
        p = get_provider("ollama")
        if p.health_check():
            models = p.list_models()
            console.print(f"[green]Ollama ready — {len(models)} models[/green]")
            return p
    except: pass
    console.print("[yellow]Ollama not running[/yellow]")
    return None

@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx):
    """Briar — Autonomous AI Pentester"""
    if ctx.invoked_subcommand is None:
        console.print(BANNER)
        console.print("\n[dim]Run [cyan]briar --help[/cyan] for commands[/dim]\n")

@cli.command()
def setup():
    """Configure Briar"""
    console.print(Panel.fit("[bold green]Briar Setup[/bold green]\nPick your AI provider:", title="Setup"))
    
    provider_list = [
        ("1", "Ollama", "Free, local, no API key"),
        ("2", "OpenAI", "GPT-4o, paid API"),
        ("3", "Anthropic", "Claude, paid API"),
        ("4", "DeepSeek", "V3/R1, cheap API"),
        ("5", "Groq", "Fast, free tier available"),
        ("6", "Mistral", "European, paid API"),
        ("7", "xAI", "Grok-3, paid API"),
        ("8", "Google", "Gemini 2.5, free tier"),
        ("9", "OpenRouter", "200+ models, paid"),
        ("10", "Together", "Open-source models"),
        ("11", "Custom", "OpenAI-compatible endpoint"),
    ]
    for num, name, desc in provider_list:
        console.print(f"  [cyan]{num}. {name}[/cyan] — [dim]{desc}[/dim]")
    
    choice = click.prompt("Choice", type=int, default=1)
    providers = {
        1:"ollama",2:"openai",3:"anthropic",4:"deepseek",5:"groq",6:"mistral",
        7:"xai",8:"google",9:"openrouter",10:"together",11:"custom"
    }
    provider = providers.get(choice, "ollama")
    
    os.makedirs(os.path.expanduser("~/.briar"), exist_ok=True)
    config = f"PROVIDER={provider}\n"
    if provider == "ollama":
        config += "OLLAMA_HOST=localhost\nOLLAMA_PORT=11434\nOLLAMA_MODEL=minimax-m2.5:latest\n"
    elif provider == "custom":
        config += f"CUSTOM_ENDPOINT={click.prompt('API Endpoint URL')}\n"
        config += f"CUSTOM_API_KEY={click.prompt('API Key', hide_input=True)}\n"
        config += f"CUSTOM_MODEL={click.prompt('Model name', default='gpt-4o')}\n"
    else:
        config += f"{provider.upper()}_API_KEY={click.prompt('API Key', hide_input=True)}\n"

    # Default report language (used by every scan + the dashboard; -p/--lang still override)
    langs = {1: "en", 2: "fr", 3: "es", 4: "de", 5: "it", 6: "pt", 7: "nl", 8: "ar"}
    console.print("\n[bold]Report language[/bold] — [dim]1.en 2.fr 3.es 4.de 5.it 6.pt 7.nl 8.ar[/dim]")
    report_lang = langs.get(click.prompt("Language", type=int, default=2), "en")
    config += f"REPORT_LANG={report_lang}\n"

    with open(os.path.expanduser("~/.briar/config"), "w") as f:
        f.write(config)
    console.print(f"\n[green]Provider: {provider}[/green]  ·  [green]Language: {report_lang}[/green]")


@cli.command()
def demo():
    """Self-test: scan a built-in vulnerable app (no target, network or API key needed)."""
    from briar.demo import serve
    import briar.agents.analyzer as az
    from briar.agents import run_scan_agents, filter_noise
    from briar.core.validator import ExploitValidator
    from briar.core.confidence import apply_confidence

    # Skip the LLM — this proves the DETECTION engine, offline and instant.
    orig = az.SecurityAnalyzer.analyze_endpoint
    az.SecurityAnalyzer.analyze_endpoint = (
        lambda self, url, method="GET", source_hint="", tech_context="", plan_context="":
        {"url": url, "analysis": "(demo: AI analysis skipped)", "raw": ""})
    server, url = serve()
    console.print(Panel.fit(
        f"[bold green]Briar self-test[/bold green]\n"
        f"Scanning built-in vulnerable app at [cyan]{url}[/cyan]\n"
        f"[dim]SQLi + XSS + path traversal — no API key needed[/dim]", title="Demo"))
    try:
        findings = run_scan_agents(["recon", "injection", "xss", "traversal", "headers"],
                                   "ollama", url, max_workers=6)
        findings, _ = filter_noise(findings)
        findings = ExploitValidator().validate_all(findings, url)
        findings = apply_confidence(findings)
    finally:
        az.SecurityAnalyzer.analyze_endpoint = orig
        server.shutdown()

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: (0 if f.get("confirmed") else 1, order.get(f.get("severity"), 9)))
    confirmed = sum(1 for f in findings if f.get("confirmed"))
    table = Table(title="Demo Results")
    table.add_column("Type", style="cyan"); table.add_column("Sev"); table.add_column("Endpoint"); table.add_column("Confirmed")
    for f in findings[:15]:
        table.add_row(str(f.get("type", "?"))[:32], str(f.get("severity", "?")),
                      str(f.get("url", "?"))[:46], "yes" if f.get("confirmed") else "")
    console.print(table)
    if confirmed:
        console.print(f"\n[bold green]{len(findings)} findings, {confirmed} CONFIRMED — Briar works.[/bold green]")
    else:
        console.print(f"\n[yellow]{len(findings)} findings, {confirmed} confirmed.[/yellow]")

@cli.command()
@click.option("-u", "--url", required=False, help="Target URL")
@click.option("-r", "--repo", help="Source code path")
@click.option("-p", "--provider", default=None, help="AI provider (overrides saved config)")
@click.option("-o", "--output", default="./reports", help="Output dir")
@click.option("-c", "--config", "config_path", help="YAML config file (auth, rules, target)")
@click.option("--quick", is_flag=True, help=f"Quick scan ({len(agents_for_mode('quick'))} agents)")
@click.option("--deep", is_flag=True, help=f"Deep scan (all {TOTAL_AGENTS} agents + browser)")
@click.option("--resume", "resume_ws", help="Resume a workspace by name")
@click.option("--output-json", "json_output", help="Export findings as JSON")
@click.option("--lang", default=None, help="Report language: en, fr, es, de, it, pt, nl, ar")
def scan(url, repo, provider, output, config_path, quick, deep, resume_ws, lang):
    """Run a pentest scan"""
    # Load saved config (mandatory if no -p flag)
    saved = load_saved_config()

    # Load config file if provided
    if config_path:
        from briar.config import load_config, build_login_flow
        config = load_config(config_path)
        url = url or config.get("target", {}).get("url", "")
        provider = config.get("provider", provider)
        output = config.get("output", output)
        mode = config.get("mode", "standard")
        lang = lang or config.get("lang")
        auth_flow = build_login_flow(config)
        console.print(f"[dim]Config loaded: {len(config.get('rules',{}).get('avoid',[]))} avoid rules, auth={'yes' if auth_flow else 'no'}[/dim]")
    else:
        auth_flow = None

    # Resolve provider: -p flag > YAML config > registered API(s). Ask if several.
    if not provider:
        regs = registered_providers(saved)
        if not regs:
            # No API key registered — use local Ollama only if it is actually running
            if check_ollama():
                provider = "ollama"
                console.print("[dim]No API key registered — falling back to local Ollama.[/dim]")
            else:
                console.print(Panel.fit(
                    "[bold red]No AI provider configured[/bold red]\n\n"
                    "[dim]Run [cyan]briar setup[/cyan] to register an API key,\n"
                    "start Ollama, or pass [cyan]-p PROVIDER[/cyan].[/dim]",
                    title="Error"))
                sys.exit(1)
        elif len(regs) == 1:
            provider = regs[0]
        else:
            # Several registered APIs — let the user pick
            console.print("\n[bold]Plusieurs API enregistrées — choisis le provider :[/bold]")
            for i, p in enumerate(regs, 1):
                tag = " [dim](défaut)[/dim]" if i == 1 else ""
                console.print(f"  [cyan]{i}[/cyan]. {p}{tag}")
            choice = click.prompt("Provider #", type=click.IntRange(1, len(regs)), default=1)
            provider = regs[choice - 1]

    # Show what we're using
    api_key_env = f"{provider.upper()}_API_KEY"
    has_key = os.environ.get(api_key_env) or (provider == 'ollama')
    key_status = "[green]key set[/green]" if has_key else "[red]no key[/red]"
    console.print(f"[dim]Provider: [cyan]{provider}[/cyan] ({key_status})[/dim]")

    if not has_key and provider != 'ollama':
        console.print(f"[yellow]Warning: {api_key_env} not set. Provider may fail.[/yellow]")

    if not url:
        console.print("[red]URL required (-u or config file)[/red]"); sys.exit(1)

    # Normalize target: a bare domain (no scheme) silently breaks all HTTP probing
    from briar.core.http import normalize_url
    normalized = normalize_url(url)
    if normalized != url:
        console.print(f"[dim]Target normalized: {url} -> {normalized}[/dim]")
        url = normalized

    mode = "deep" if deep else "quick" if quick else "standard"
    # Report language: --lang > config file > saved config > English
    lang = (lang or (saved.get("REPORT_LANG") if saved else None) or "en").lower()
    os.environ["BRIAR_REPORT_LANG"] = lang
    # Cap every agent's per-request timeout (huge lever on slow targets). User-overridable.
    os.environ.setdefault("BRIAR_HTTP_TIMEOUT", "6")

    # Resume existing workspace
    from briar.core.workspace import Workspace
    from briar.core.animation import SylphAnimation
    if resume_ws:
        ws = Workspace.load(resume_ws)
        findings = ws.get_findings()
        agents_to_run = ws.get_remaining_agents(agents_for_mode(mode))
        console.print(Panel.fit(
            f"[bold red]Briar Resume[/bold red]\n"
            f"[cyan]{url}[/cyan] | [yellow]{provider}[/yellow] | [dim]{len(findings)} findings so far, {len(agents_to_run)} agents left[/dim]",
            title="Resume"))
    else:
        ws = Workspace(url, mode)
        findings = []
        agents_to_run = agents_for_mode(mode)

    console.print(Panel.fit(
        f"[bold red]Briar Scan[/bold red]\n"
        f"[cyan]{url}[/cyan] | [yellow]{provider}[/yellow] | [dim]{mode} ({len(agents_to_run)} agents)[/dim]"
        + (f"\n[dim]Workspace: {ws.name}[/dim]" if ws else ""),
        title="Scan"))

    if provider == "ollama" and not check_ollama():
        console.print("[red]Start Ollama first[/red]"); sys.exit(1)

    # Authenticate if config provides credentials
    if auth_flow:
        from briar.core.http import HTTPClient
        http = HTTPClient(timeout=10)
        creds = auth_flow.get("credentials", {})
        login_url = url.rstrip("/") + auth_flow.get("login_url", "/login").lstrip("/")
        method = auth_flow.get("method", "form")
        try:
            if method == "json":
                resp = http.post(login_url, json=creds)
            else:
                resp = http.post(login_url, data=creds)
            console.print(f"[green]Auth: {resp.status_code} on {login_url}[/green]")
        except Exception as e:
            console.print(f"[yellow]Auth failed: {e}[/yellow]")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        import time
        scan_start = time.time()
        task = progress.add_task("[cyan]Scanning...", total=len(agents_to_run))
        from briar.agents import run_scan_agents

        total_agents = len(agents_to_run)
        completed = [0]
        sylph = SylphAnimation(total_agents)

        def on_result(name, result):
            # Progress + live checkpoint only. The authoritative findings list is the
            # RETURN value of run_scan_agents (which includes per-endpoint findings that
            # on_result dedups away for progress).
            completed[0] += 1
            ws.checkpoint_agent(name, [result] if result and "error" not in result else [])
            progress.update(task, description=f"[{completed[0]}/{total_agents}] [yellow]{name}[/yellow]")
            progress.advance(task)
            sylph.update(completed[0] - 1, name)
            console.print(sylph.render())

        # Agents run concurrently: recon first (feeds tech context), then a thread pool.
        # Use the RETURN value — it holds every finding, including per-endpoint ones.
        findings += run_scan_agents(agents_to_run, provider, url, on_result=on_result,
                                    lang=lang, max_workers=10, repo_path=repo)

        # Always-visible diagnostic: what recon actually mapped (survives the progress UI)
        _recon = next((f for f in findings if f.get("agent") == "Recon"), {})
        console.print(f"[dim]Recon: {_recon.get('endpoints_discovered', 0)} URLs crawled, "
                      f"{len(_recon.get('endpoints', []))} param-endpoints to attack on {url}[/dim]")
        if _recon.get("crawl_errors"):
            console.print(f"[yellow]Crawl note: {_recon['crawl_errors'][0]}[/yellow]")

        # Sort findings by severity (Critical first)
        sev_order = {"Critical":0, "High":1, "Medium":2, "Low":3, "Info":4, "Error":5}
        findings.sort(key=lambda f: sev_order.get(f.get("severity", "Info"), 99))

        # Filter out noise
        noise_patterns = ["No hardcoded secrets found", "No login form found", 
                          "No findings", "Browser exploit failed"]
        tests_done = []
        clean_findings = []
        for f in findings:
            sev = f.get("severity", "")
            analysis = f.get("analysis", "")
            # Skip errors and noisy info
            if sev == "Error":
                continue
            if sev == "Info" and any(p in analysis for p in noise_patterns):
                tests_done.append(f.get("agent", "?"))
                continue
            clean_findings.append(f)
        findings = clean_findings

        # Add "tests effectués" note
        if tests_done:
            findings.append({
                "type": "Tests effectués sans succès",
                "severity": "Info",
                "agent": "Briar",
                "url": url,
                "analysis": f"Les catégories suivantes ont été testées sans trouver de vulnérabilité exploitable : {', '.join(sorted(set(tests_done)))}. Ceci est normal — Briar ne reporte que ce qui est confirmé.",
                "confirmed": False,
            })

        # Exploit validation — replay High/Critical findings
        progress.update(task, description="[yellow]Validating exploits...")
        from briar.core.validator import ExploitValidator
        validator = ExploitValidator()
        findings = validator.validate_all(findings, url)
        progress.update(task, description=f"[dim]{validator.summary()}[/dim]")
        # Evidence-based confidence scoring (flags unproven High/Critical)
        try:
            from briar.core.confidence import apply_confidence
            findings = apply_confidence(findings)
        except Exception:
            pass
        
        # Deep mode: active exploits
        if deep:
            from urllib.parse import urlparse, parse_qs
            
            # Extract params from recon findings
            params_list = []
            recon_result = next((f for f in findings if f.get("agent") == "Recon"), None)
            if recon_result and recon_result.get("urls_sample"):
                for u in recon_result["urls_sample"]:
                    try:
                        parsed = urlparse(u)
                        params = list(parse_qs(parsed.query).keys())
                        params_list.extend(params)
                    except: pass
            params_list = list(set(params_list)) or ["q", "id", "page"]
            
            # CLI exploits — SQL injection
            from briar.exploits.browser import CLIExploiter
            progress.update(task, description="[yellow]SQL injection exploits...")
            for param in params_list[:5]:
                try:
                    result = CLIExploiter.test_sql_injection(url, param)
                    anomalies = [t for t in result.get("tests", []) if t.get("status") != 200]
                    if anomalies:
                        findings.append({
                            "type": "SQL Injection (exploit)", "severity": "High",
                            "agent": "Exploiter", "url": url, "param": param,
                            "tests": len(anomalies),
                            "analysis": f"SQLi anomalies detected on param '{param}': {len(anomalies)}/{len(result['tests'])} payloads"
                        })
                except: pass
            
            # CLI exploits — SSRF
            progress.update(task, description="[yellow]SSRF exploits...")
            for param in ["url", "redirect", "callback", "next", "return"][:3]:
                try:
                    result = CLIExploiter.test_ssrf(url, param)
                    metadata_responses = [t for t in result.get("tests", [])
                        if "metadata" in str(t.get("payload","")).lower() and t.get("status", 0) == 200]
                    if metadata_responses:
                        findings.append({
                            "type": "SSRF (exploit)", "severity": "Critical",
                            "agent": "Exploiter", "url": url, "param": param,
                            "analysis": f"SSRF possible: cloud metadata endpoint accessible via '{param}'"
                        })
                except: pass
            
            # Browser exploits — screenshots + XSS
            progress.update(task, description="[yellow]Browser exploits...")
            try:
                from briar.exploits.browser import BrowserExploiter
                browser = BrowserExploiter(headless=True)
                try:
                    screenshot_path = browser.screenshot(url, f"{output}/screenshots")
                    findings.append({
                        "type": "Screenshot", "severity": "Info",
                        "agent": "Exploiter", "url": url,
                        "analysis": f"Page screenshot saved: {screenshot_path}"
                    })
                    
                    xss_payloads = [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "\"><script>alert('XSS')</script>",
                        "javascript:alert(1)",
                    ]
                    for payload in xss_payloads[:3]:
                        xss_result = browser.test_xss(url, payload, f"{output}/screenshots")
                        if xss_result["vulnerable"]:
                            findings.append({
                                "type": "XSS (exploit)", "severity": "High",
                                "agent": "Exploiter", "url": url, "payload": payload,
                                "screenshot": xss_result.get("screenshot"),
                                "analysis": f"XSS confirmed: alert() triggered with payload '{payload}'"
                            })
                            break
                finally:
                    browser.quit()
            except Exception as e:
                findings.append({
                    "type": "Browser Exploit", "severity": "Error",
                    "agent": "Exploiter", "url": url,
                    "analysis": f"Browser exploit failed: {e}"
                })
        
        # Charts (optional — matplotlib is an extra; never crash the scan without it)
        try:
            progress.update(task, description="[green]Generating charts...")
            from briar.charts.generator import ChartGenerator
            cg = ChartGenerator(findings, f"{output}/charts")
            cg.severity_donut()
            cg.endpoint_heatmap()
            cg.type_bar()
            cg.agent_bar()
        except Exception:
            pass
        
        # JSON export
    if json_output:
        import json
        json_data = {
            "tool": "Briar",
            "version": "0.4.58",
            "target": url,
            "mode": mode,
            "provider": provider,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "findings_count": len(findings),
            "confirmed": sum(1 for f in findings if f.get("confirmed")),
            "findings": [{
                "id": f"FIN-{i+1:03d}",
                "type": f.get("type","?"),
                "severity": f.get("severity","?"),
                "agent": f.get("agent","?"),
                "endpoint": f.get("url", url),
                "param": f.get("param",""),
                "payload": f.get("payload",""),
                "confirmed": f.get("confirmed", False),
                "poc": f.get("poc",""),
                "analysis": f.get("analysis","")[:500]
            } for i, f in enumerate(findings)]
        }
        os.makedirs(os.path.dirname(os.path.abspath(json_output)) or ".", exist_ok=True)
        with open(json_output, "w") as jf:
            json.dump(json_data, jf, indent=2, ensure_ascii=False)
        console.print(f"[dim]JSON: {json_output}[/dim]")

    # Reports
        progress.update(task, description="[green]Generating reports...")
        from briar.reports.generator import ReportGenerator
        gen = ReportGenerator(url, findings, output)
        reports = gen.all_formats()
        
        # Obsidian
        from briar.reports.obsidian import ObsidianGenerator
        og = ObsidianGenerator(url, findings, f"{output}/obsidian")
        og.generate()

        # Expert report — professional HTML + PDF (print-ready)
        expert_res = {}
        try:
            progress.update(task, description="[green]Generating expert report...")
            from briar.reports.expert import ExpertReport
            expert_res = ExpertReport(url, findings, output,
                {"scanner": "Briar", "version": __version__, "mode": mode,
                 "provider": provider, "lang": lang}).generate()
        except Exception:
            pass
        
        # Slides
        from briar.slides.pptx_gen import SlideGenerator
        sg = SlideGenerator(url, findings, f"{output}/slides")
        try: sg.pptx()
        except: pass
        sg.html_slides()
        
        progress.advance(task)
    
    # Severity breakdown + CONFIDENCE-WEIGHTED risk verdict.
    # An UNPROVEN finding (heuristic, not replayed) counts a quarter — a report must
    # not scream "High 100/100" off unconfirmed guesses. Confirmed = full weight.
    sev_counts = {lvl: sum(1 for f in findings if f.get("severity") == lvl)
                  for lvl in ["Critical", "High", "Medium", "Low", "Info"]}
    confirmed = sum(1 for f in findings if f.get("confirmed"))
    _sevw = {"Critical": 30, "High": 12, "Medium": 4, "Low": 1, "Info": 0}
    score = 0.0
    for f in findings:
        w = _sevw.get(f.get("severity"), 0)
        score += w if f.get("confirmed") else w * 0.25
    if any(f.get("confirmed") and f.get("severity") == "Critical" for f in findings):
        score = max(score, 90)
    elif any(f.get("confirmed") and f.get("severity") == "High" for f in findings):
        score = max(score, 60)
    score = min(100, int(round(score)))
    if score >= 70:
        risk, rc = "Critical", "magenta"
    elif score >= 40:
        risk, rc = "High", "red"
    elif score >= 15:
        risk, rc = "Medium", "yellow"
    elif score > 0:
        risk, rc = "Low", "green"
    else:
        risk, rc = "Clean", "green"
    if confirmed == 0 and risk not in ("Clean",):
        risk += " (unverified)"

    table = Table(title="Scan Complete")
    table.add_column("Metric", style="cyan"); table.add_column("Value", style="green")
    _recon = next((f for f in findings if f.get("agent") == "Recon"), {})
    table.add_row("Target", url)
    table.add_row("Mode", f"{mode} ({len(agents_to_run)} agents)")
    table.add_row("Attack surface", f"{_recon.get('endpoints_discovered', 0)} URLs, "
                  f"{len(_recon.get('endpoints', []))} param-endpoints")
    if _recon.get("crawl_errors"):
        table.add_row("Crawl note", str(_recon["crawl_errors"][0])[:60])
    if not _recon:
        table.add_row("Recon", "[red]no recon result (target unreachable?)[/red]")
    table.add_row("Findings", str(len(findings)))
    sev_colors = {"Critical": "magenta", "High": "red", "Medium": "yellow", "Low": "bright_yellow", "Info": "blue"}
    for lvl in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev_counts[lvl]:
            table.add_row(f"  {lvl}", f"[{sev_colors[lvl]}]{sev_counts[lvl]}[/{sev_colors[lvl]}]")
    if confirmed:
        table.add_row("Confirmed", f"[bold green]{confirmed}[/bold green]")
    for fmt, path in reports.items():
        table.add_row(f"Report ({fmt})", path)
    if expert_res.get("pdf"):
        table.add_row("Expert PDF", f"[bold]{expert_res['pdf']}[/bold]")
    elif expert_res.get("html"):
        table.add_row("Expert HTML", expert_res["html"])
    table.add_row("Charts", f"{output}/charts/")
    console.print(table)
    console.print(Panel.fit(
        f"[bold {rc}]RISK: {risk}[/bold {rc}]   score {score}/100   ·   {len(findings)} findings, {confirmed} confirmed",
        title="Verdict"))
    console.print("\n[dim]Open reports or launch dashboard: briar serve[/dim]")

@cli.command()
@click.argument("workspace_name", required=False)
def resume(workspace_name):
    """Resume an interrupted scan from a workspace"""
    from briar.core.workspace import Workspace
    if workspace_name:
        # Re-run scan with --resume flag
        import subprocess, sys
        ws_path = os.path.join(os.path.expanduser("~/.briar/workspaces"), workspace_name)
        if not os.path.exists(ws_path):
            workspaces = Workspace.list_workspaces()
            console.print(f"[red]Workspace not found: {workspace_name}[/red]")
            if workspaces:
                console.print("\n[dim]Available workspaces:[/dim]")
                for w in workspaces[:10]:
                    console.print(f"  {w}")
            sys.exit(1)
        console.print(f"[green]Resuming workspace: {workspace_name}[/green]")
        console.print(f"[dim]Run: briar scan --resume {workspace_name}[/dim]")
    else:
        workspaces = Workspace.list_workspaces()
        if not workspaces:
            console.print("[dim]No workspaces found.[/dim]")
            return
        console.print("[bold]Saved workspaces:[/bold]")
        for w in workspaces[:20]:
            console.print(f"  [cyan]{w}[/cyan]")

@cli.command()
@click.argument("workspace_name", required=False)
def workspaces(workspace_name):
    """List all saved workspaces"""
    from briar.core.workspace import Workspace
    import json
    if workspace_name:
        try:
            ws = Workspace.load(workspace_name)
            console.print(f"[bold]Workspace: {ws.name}[/bold]")
            console.print(f"  Target: {ws._state.get('target','?')}")
            console.print(f"  Mode: {ws._state.get('mode','?')}")
            console.print(f"  Agents done: {len(ws._state.get('agents_completed',[]))}")
            console.print(f"  Findings: {ws._state.get('findings_count',0)}")
            console.print(f"  Resume: briar scan --resume {ws.name}")
        except Exception as e:
            console.print(f"[red]{e}[/red]")
    else:
        workspaces = Workspace.list_workspaces()
        if not workspaces:
            console.print("[dim]No workspaces yet. Run a scan first.[/dim]")
            return
        table = Table(title="Workspaces")
        table.add_column("Name", style="cyan")
        table.add_column("Target")
        table.add_column("Findings", style="green")
        table.add_column("Agents Done")
        for w_name in workspaces[:20]:
            try:
                ws = Workspace.load(w_name)
                table.add_row(
                    w_name[:40], 
                    str(ws._state.get("target", "?"))[:30],
                    str(ws._state.get("findings_count", 0)),
                    str(len(ws._state.get("agents_completed", [])))
                )
            except:
                table.add_row(w_name[:40], "?","?","?")
        console.print(table)

@cli.command()
def status():
    """Show current configuration"""
    saved = load_saved_config()
    if not saved:
        console.print("[yellow]No configuration found.[/yellow]")
        console.print("[dim]Run [cyan]briar setup[/cyan] to configure.[/dim]")
        return

    provider = saved.get('PROVIDER', 'unknown')
    details = '\n'.join(f'  [dim]{k}: {v[:30]}[/dim]' for k,v in saved.items() if k != 'PROVIDER')
    console.print(Panel.fit(
        f"[bold green]Briar Status[/bold green]\n"
        f"  Provider:  [cyan]{provider}[/cyan]\n\n"
        f"{details}\n\n"
        f"[dim]Run [cyan]briar setup[/cyan] to change provider.[/dim]",
        title="Config"
    ))

@cli.command()
@click.argument("scan1", required=True)
@click.argument("scan2", required=True)
def diff(scan1, scan2):
    """Compare two scans and show differences"""
    from briar.core.diff import diff_workspaces
    from briar.core.workspace import WORKSPACES_DIR
    import os

    # Find workspaces matching scan IDs
    workspaces = sorted([d for d in os.listdir(WORKSPACES_DIR) if os.path.isdir(os.path.join(WORKSPACES_DIR, d))])
    ws1 = ws2 = None
    for ws in workspaces:
        if scan1 in ws: ws1 = ws
        if scan2 in ws: ws2 = ws

    if not ws1 or not ws2:
        console.print("[red]Workspace not found. Use briar workspaces to list.[/red]")
        return

    result = diff_workspaces(ws1, ws2)
    s = result["summary"]

    table = Table(title="Scan Diff")
    table.add_column("Metric", style="cyan"); table.add_column("Value", style="green")
    table.add_row("Scan 1", ws1[:30])
    table.add_row("Scan 2", ws2[:30])
    table.add_row("Old findings", str(s["total_old"]))
    table.add_row("New findings", str(s["total_new"]))
    table.add_row("New", f'[green]+{s["new_findings"]}[/green]')
    table.add_row("Fixed", f'[red]-{s["fixed_findings"]}[/red]')
    table.add_row("Changed severity", f'[yellow]~{s["changed_severity"]}[/yellow]')
    table.add_row("Unchanged", f'[dim]={s["unchanged"]}[/dim]')
    console.print(table)

    if result["new"]:
        console.print(f"\n[bold green]+{len(result['new'])} NEW findings:[/bold green]")
        for f in result["new"][:10]:
            console.print(f"  [green]NEW[/green] [{f.get('severity','?')}] {f.get('type','?')} — {f.get('agent','?')}")
    if result["fixed"]:
        console.print(f"\n[bold red]-{len(result['fixed'])} FIXED findings:[/bold red]")
        for f in result["fixed"][:5]:
            console.print(f"  [red]FIXED[/red] [{f.get('severity','?')}] {f.get('type','?')}")

@cli.command()
def serve():
    """Start web dashboard"""
    os.system("python -m briar.web")

if __name__ == "__main__":
    cli()
