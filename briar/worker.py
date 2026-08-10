"""Briar Worker — background scan executor with file-based job queue"""
import json, os, time, sys
from pathlib import Path

JOBS_FILE = os.path.expanduser("~/.briar/jobs.json")

def load_jobs():
    try:
        with open(JOBS_FILE) as f:
            return json.load(f)
    except:
        return []

def save_jobs(jobs):
    os.makedirs(os.path.dirname(JOBS_FILE), exist_ok=True)
    with open(JOBS_FILE, "w") as f:
        json.dump(jobs, f, indent=2)

def process_job(job):
    """Execute a single scan job (concurrent pipeline, same as CLI/dashboard)."""
    from briar.agents import agents_for_mode, run_scan_agents, filter_noise
    url = job["url"]
    provider = job.get("provider", "ollama")
    mode = job.get("mode", "standard")
    lang = job.get("lang")
    os.environ.setdefault("BRIAR_HTTP_TIMEOUT", "6")

    agents = agents_for_mode(mode)
    findings = run_scan_agents(agents, provider, url, lang=lang)
    findings, _ = filter_noise(findings)
    return {"url": url, "findings": len(findings), "errors": 0, "agents_ran": len(agents)}

def main():
    print("🥀 Briar Worker v0.1.0 — waiting for jobs...")
    while True:
        jobs = load_jobs()
        pending = [j for j in jobs if j.get("status") == "pending"]

        for job in pending:
            print(f"[Worker] Processing: {job['url']} ({job.get('provider','ollama')})")
            job["status"] = "running"
            save_jobs(jobs)

            try:
                result = process_job(job)
                job["status"] = "done"
                job["result"] = result
                job["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                print(f"[Worker] Done: {job['url']} — {result['findings']} findings")
            except Exception as e:
                job["status"] = "failed"
                job["error"] = str(e)
                print(f"[Worker] Failed: {job['url']} — {e}")

            save_jobs(jobs)

        time.sleep(5)

if __name__ == "__main__":
    main()
