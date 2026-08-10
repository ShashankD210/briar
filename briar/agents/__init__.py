"""Briar agent registry — single source of truth for the agent roster."""
import os
from .analyzer import SecurityAnalyzer
from .recon import ReconAgent
from .planner import PlannerAgent
from .gitbackup import GitBackupAgent
from .headers import HeadersAgent
from .cve import CVEAgent
from .secrets import SecretsAgent
from .info_disclosure import InfoDisclosureAgent
from .backup_files import BackupFilesAgent
from .cache import CacheAgent
from .cors import CORSAgent
from .crlf import CRLFAgent
from .graphql import GraphQLAgent
from .headers import HeadersAgent
from .host_header import HostHeaderAgent
from .idor import IDORAgent
from .nosql import NoSQLAgent
from .nuclei import NucleiAgent
from .session import SessionAgent
from .ssti import SSTIAgent
from .xxe import XXEAgent
from .backup_files import BackupFilesAgent
from .admin_panel import AdminPanelAgent
from .injection import InjectionAgent
from .nosql import NoSQLAgent
from .xss import XSSAgent
from .ssti import SSTIAgent
from .ssrf import SSRFAgent
from .xxe import XXEAgent
from .rce import RCEAgent
from .crlf import CRLFAgent
from .traversal import TraversalAgent
from .upload import UploadAgent
from .auth import AuthAgent
from .authz import AuthZAgent
from .idor import IDORAgent
from .session import SessionAgent
from .jwt import JWTAgent
from .wordpress import WordPressAgent
from .admin_panel import AdminPanelAgent
from .open_redirect import OpenRedirectAgent
from .info_disclosure import InfoDisclosureAgent
from .backup_files import BackupFilesAgent
from .cache import CacheAgent
from .cors import CORSAgent
from .crlf import CRLFAgent
from .graphql import GraphQLAgent
from .headers import HeadersAgent
from .host_header import HostHeaderAgent
from .idor import IDORAgent
from .nosql import NoSQLAgent
from .nuclei import NucleiAgent
from .session import SessionAgent
from .ssti import SSTIAgent
from .xxe import XXEAgent
from .csrf import CSRFAgent
from .cors import CORSAgent
from .open_redirect import OpenRedirectAgent
from .host_header import HostHeaderAgent
from .graphql import GraphQLAgent
from .cache import CacheAgent
from .api import APIAgent
from .nuclei import NucleiAgent

# name -> class. Recon stays first so its tech stack feeds every later agent.
AGENTS = {
    "recon": ReconAgent,
    "headers": HeadersAgent,
    "secrets": SecretsAgent,
    "info_disclosure": InfoDisclosureAgent,
    "backup_files": BackupFilesAgent,
    "cache": CacheAgent,
    "cors": CORSAgent,
    "crlf": CRLFAgent,
    "graphql": GraphQLAgent,
    "headers": HeadersAgent,
    "host_header": HostHeaderAgent,
    "idor": IDORAgent,
    "nosql": NoSQLAgent,
    "nuclei": NucleiAgent,
    "session": SessionAgent,
    "ssti": SSTIAgent,
    "xxe": XXEAgent,
    "injection": InjectionAgent,
    "xss": XSSAgent,
    "ssrf": SSRFAgent,
    "cve": CVEAgent,
    "auth": AuthAgent,
    "authz": AuthZAgent,
    "idor": IDORAgent,
    "rce": RCEAgent,
    "traversal": TraversalAgent,
    "csrf": CSRFAgent,
    "admin_panel": AdminPanelAgent,
    "backup_files": BackupFilesAgent,
    "planner": PlannerAgent,
    "gitbackup": GitBackupAgent,
    "nosql": NoSQLAgent,
    "ssti": SSTIAgent,
    "xxe": XXEAgent,
    "crlf": CRLFAgent,
    "upload": UploadAgent,
    "session": SessionAgent,
    "jwt": JWTAgent,
    "wordpress": WordPressAgent,
    "admin_panel": AdminPanelAgent,
    "open_redirect": OpenRedirectAgent,
    "info_disclosure": InfoDisclosureAgent,
    "backup_files": BackupFilesAgent,
    "cache": CacheAgent,
    "cors": CORSAgent,
    "crlf": CRLFAgent,
    "graphql": GraphQLAgent,
    "headers": HeadersAgent,
    "host_header": HostHeaderAgent,
    "idor": IDORAgent,
    "nosql": NoSQLAgent,
    "nuclei": NucleiAgent,
    "session": SessionAgent,
    "ssti": SSTIAgent,
    "xxe": XXEAgent,
    "cors": CORSAgent,
    "open_redirect": OpenRedirectAgent,
    "host_header": HostHeaderAgent,
    "graphql": GraphQLAgent,
    "cache": CacheAgent,
    "api": APIAgent,
    "nuclei": NucleiAgent,
}

# Canonical run order. The slice points below define the scan tiers, so the
# first N entries are the highest-signal agents. recon MUST stay at index 0.
AGENT_ORDER = [
    # quick (0-7): recon + fast high-signal checks
    "recon", "headers", "secrets", "info_disclosure",
    "injection", "xss", "ssrf", "cve",
    # standard adds (8-15): core active exploitation
    "auth", "authz", "idor", "rce",
    "traversal", "csrf", "admin_panel", "backup_files",
    # deep adds (16-30): full coverage
    "planner", "gitbackup", "nosql", "ssti", "xxe", "crlf",
    "upload", "session", "jwt", "cors", "open_redirect",
    "host_header", "graphql", "cache", "api", "nuclei",
]

# Number of agents per scan tier. None = the whole roster.
SCAN_MODES = {"quick": 8, "standard": 16, "deep": None}

TOTAL_AGENTS = len(AGENT_ORDER)


def agents_for_mode(mode: str) -> list:
    """Return the ordered agent names to run for a given scan mode."""
    n = SCAN_MODES.get(mode, SCAN_MODES["standard"])
    return list(AGENT_ORDER) if n is None else AGENT_ORDER[:n]


def agent_count(mode: str) -> int:
    """Number of agents a given mode will run."""
    return len(agents_for_mode(mode))


def run_agent(name, provider="ollama", lang=None, **kwargs):
    if name not in AGENTS:
        return {"error": f"Agent '{name}' not found. Available: {list(AGENTS.keys())}"}
    agent = AGENTS[name](provider)
    # Report language (analysis output) — set per-instance so it is thread-safe
    if lang and hasattr(agent, 'analyzer'):
        agent.analyzer.set_language(lang)
    # Inject tech context (from recon) if the agent's analyzer can use it
    recon_data = kwargs.pop("recon_data", None)
    if recon_data and hasattr(agent, 'analyzer'):
        from briar.agents.analyzer import build_tech_context
        kwargs["tech_context"] = build_tech_context(recon_data)
    # Forward recon_data itself to agents that consume it (e.g. planner). Every
    # agent's scan(**kwargs) tolerates the extra kwarg.
    if recon_data is not None:
        kwargs["recon_data"] = recon_data
    return agent.scan(**kwargs)


NOISE_PATTERNS = ["No hardcoded secrets found", "No login form found",
                  "No findings", "Browser exploit failed", "No issues detected"]


def filter_noise(findings):
    """Drop Error findings and empty 'nothing found' Info noise. Keeps recon and any
    Info finding that carries real evidence. Returns (clean, tests_done_agents)."""
    clean, tests_done = [], []
    for f in findings:
        sev = f.get("severity", "")
        if sev == "Error":
            continue
        if sev == "Info":
            # Recon always stays. Other Info findings are kept only if they carry real
            # evidence and aren't a "nothing found" note — this turns 56 Info into signal.
            if f.get("agent") == "Recon":
                clean.append(f)
                continue
            evidenced = bool(f.get("real_findings")) or bool(f.get("confirmed"))
            noisy = any(p in str(f.get("analysis", "")) for p in NOISE_PATTERNS)
            if not evidenced or noisy:
                tests_done.append(f.get("agent", "?"))
                continue
        clean.append(f)
    return clean, tests_done


# Agents that attack a parameterized endpoint — routed against every discovered
# endpoint (with real params), not just the root URL.
PARAM_AGENTS = {"injection", "xss", "ssrf", "traversal", "rce",
                "nosql", "ssti", "crlf", "open_redirect"}


def _attack_targets(base_url, recon_data, cap=4):
    """Base URL + top crawled endpoints that carry a query string (real params)."""
    targets = [base_url]
    if isinstance(recon_data, dict):
        for e in (recon_data.get("endpoints") or []):
            if isinstance(e, str) and "?" in e and e not in targets:
                targets.append(e)
                if len(targets) > cap:
                    break
    return targets


def run_scan_agents(agent_names, provider="ollama", url=None, recon_data=None,
                    on_result=None, max_workers=10, repo_path=None, lang=None):
    """Run a scan: recon first (maps the attack surface), then every agent
    concurrently. Param-based agents are routed against each discovered endpoint
    (with its real params), not just the root URL.

    on_result(name, result) fires once per agent (for progress/checkpoint).
    Returns the list of successful findings (may be several per param-agent).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    names = list(agent_names)
    findings = []
    reported = set()

    def record(name, res):
        if res and "error" not in res:
            findings.append(res)
        if os.environ.get("BRIAR_DEBUG"):
            ok = bool(res) and "error" not in res
            rf = len(res.get("real_findings", [])) if isinstance(res, dict) else 0
            print(f"[briar-debug] {name}: {'ok' if ok else 'skip/err'} "
                  f"sev={res.get('severity') if isinstance(res, dict) else '?'} real_findings={rf}", flush=True)
        if on_result and name not in reported:
            reported.add(name)
            try:
                on_result(name, res)
            except Exception:
                pass

    # Recon first — its crawl feeds the endpoint list and tech context.
    if "recon" in names:
        names.remove("recon")
        try:
            r = run_agent("recon", provider, url=url, repo_path=repo_path, lang=lang)
        except Exception as e:
            r = {"error": str(e)}
        if r and "error" not in r:
            recon_data = r
        record("recon", r)
        # Reachability gate: abort ONLY if recon got no HTTP response at all (dead
        # host). A secondary error (parse/portscan) with a valid status must NOT abort.
        no_response = (not isinstance(recon_data, dict)) or (recon_data.get("error") and not recon_data.get("status"))
        if no_response:
            for n in names:
                record(n, {"error": "target unreachable (recon got no response)"})
            return findings

    targets = _attack_targets(url, recon_data)
    if os.environ.get("BRIAR_DEBUG"):
        st = recon_data.get("status") if isinstance(recon_data, dict) else None
        eps = recon_data.get("endpoints") if isinstance(recon_data, dict) else None
        print(f"[briar-debug] recon status={st} crawled_endpoints={len(eps or [])} "
              f"attack_targets={targets}", flush=True)

    # One job per (agent, target). Param agents fan out over endpoints; others hit root.
    jobs = []
    for name in names:
        if name in PARAM_AGENTS and len(targets) > 1:
            for t in targets:
                jobs.append((name, t))
        else:
            jobs.append((name, url))

    def work(job):
        name, target = job
        try:
            return name, run_agent(name, provider, url=target, repo_path=repo_path,
                                   recon_data=recon_data, lang=lang)
        except Exception as e:
            return name, {"error": str(e)}

    if jobs:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for fut in as_completed([pool.submit(work, j) for j in jobs]):
                name, res = fut.result()
                record(name, res)
    return findings
