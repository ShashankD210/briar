"""Nuclei Agent — runs the nuclei template engine and AI-triages the results."""
import shutil, subprocess, json
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient


# nuclei severity -> Briar severity
_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Info",
}


class NucleiAgent:
    """Wraps the nuclei binary, parses its JSONL output, and adds an AI synthesis."""

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=10)
        self.name = "Nuclei"

    def scan(self, url: str, tech_context: str = "", **kwargs) -> dict:
        findings = []
        binary = shutil.which("nuclei")

        if not binary:
            # nuclei is not installed: return a clean, informative finding and skip the heavy scan
            install_hint = "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            findings.append({
                "type": "Nuclei not installed",
                "severity": "Info",
                "analysis": install_hint,
                "nuclei": True,
            })
            analysis = f"Nuclei binary not found on this host. {install_hint}"
        else:
            findings = self._run_nuclei(binary, url)
            analysis = self._summarize(findings)

        result = self.analyzer.analyze_endpoint(url, "GET", tech_context=tech_context, source_hint=analysis)
        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "Nuclei Templates"
        result["severity"] = self._severity(findings)
        return result

    def _run_nuclei(self, binary: str, url: str) -> list:
        """Run nuclei against the target and parse the JSONL output. Never raises."""
        findings = []
        cmd = [
            binary, "-u", url,
            "-jsonl", "-silent", "-nc",
            "-disable-update-check",
            "-timeout", "5",
            "-retries", "1",
            "-severity", "info,low,medium,high,critical",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            findings.append({
                "type": "Nuclei scan timed out",
                "severity": "Info",
                "analysis": "nuclei did not finish within 180s; results may be incomplete.",
                "nuclei": True,
            })
            return findings
        except Exception as e:
            findings.append({
                "type": "Nuclei execution error",
                "severity": "Info",
                "analysis": f"Failed to run nuclei: {e}",
                "nuclei": True,
            })
            return findings

        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            parsed = self._parse_result(obj)
            if parsed:
                findings.append(parsed)
        return findings

    def _parse_result(self, obj: dict) -> dict:
        """Turn one nuclei JSONL object into a Briar finding. Never raises."""
        try:
            info = obj.get("info", {}) or {}
            classification = info.get("classification", {}) or {}

            raw_sev = str(info.get("severity", "info")).lower().strip()
            severity = _SEVERITY_MAP.get(raw_sev, "Info")

            cve = None
            cve_id = classification.get("cve-id")
            if cve_id:
                # cve-id can be a list or a string
                cve = cve_id[0] if isinstance(cve_id, list) and cve_id else cve_id

            cvss = classification.get("cvss-score")

            return {
                "type": info.get("name", "Nuclei match"),
                "severity": severity,
                "template_id": obj.get("template-id"),
                "matched_at": obj.get("matched-at"),
                "cve": cve,
                "cvss": cvss,
                "tags": info.get("tags"),
                "reference": info.get("reference"),
                "description": info.get("description"),
                "nuclei": True,
            }
        except Exception:
            return None

    def _summarize(self, findings: list) -> str:
        """Build a text summary of nuclei findings for the AI synthesis."""
        real = [f for f in findings if f.get("template_id") or f.get("cve") or f.get("matched_at")]
        if not real:
            return "Nuclei ran but reported no template matches on this target."

        counts = {}
        for f in real:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1
        count_str = ", ".join(f"{n} {s}" for s, n in
                              sorted(counts.items(), key=lambda x: ["Critical", "High", "Medium", "Low", "Info"].index(x[0])))

        lines = [f"Nuclei found {len(real)} match(es): {count_str}."]
        for f in real:
            name = f.get("type", "match")
            sev = f.get("severity", "Info")
            extra = ""
            if f.get("cve"):
                extra += f" [{f['cve']}]"
            if f.get("cvss"):
                extra += f" (CVSS {f['cvss']})"
            if f.get("matched_at"):
                extra += f" at {f['matched_at']}"
            lines.append(f"- [{sev}] {name}{extra}")
        return "\n".join(lines)

    @staticmethod
    def _severity(findings):
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            if any(f.get("severity") == s for f in findings):
                return s
        return "Info"
