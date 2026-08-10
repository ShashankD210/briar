"""WordPress Security Agent — WP-specific vulnerabilities 🎯"""
from briar.agents.analyzer import SecurityAnalyzer
from briar.core.http import HTTPClient

class WordPressAgent:
    """Discovers WordPress-specific vulnerabilities."""

    COMMON_PLUGINS = [
        "wordpress-seo", "woocommerce", "contact-form-7", "elementor",
        "akismet", "jetpack", "wordfence", "all-in-one-wp-migration",
        "wp-file-manager", "duplicator", "revslider", "w3-total-cache",
        "litespeed-cache", "wp-rocket", "updraftplus", "ninja-forms",
        "gravityforms", "mailchimp-for-wp", "really-simple-ssl",
    ]

    COMMON_THEMES = [
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
        "divi", "astra", "oceanwp", "generatepress", "hello-elementor",
        "neve", "kadence", "blocksy",
    ]

    def __init__(self, provider="ollama"):
        self.analyzer = SecurityAnalyzer(provider)
        self.http = HTTPClient(timeout=8)
        self.name = "WordPress"

    def scan(self, url: str, **kwargs) -> dict:
        findings = []
        base = url.rstrip("/")

        # 1. Detect if it's WordPress
        try:
            resp = self.http.get(base)
            html = resp.text
            is_wp = any(marker in html.lower() for marker in ["wp-content", "wp-includes", "wordpress", "wp-json"])
        except:
            is_wp = False

        if not is_wp:
            return {"type": "WordPress Scan", "severity": "Info", "agent": self.name,
                    "analysis": "Target does not appear to be WordPress.", "real_findings": []}

        # 2. User enumeration
        for uid in [1, 2, 3]:
            try:
                r = self.http.get(f"{base}/?author={uid}", allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 500:
                    findings.append({
                        "type": "WP User Enumeration",
                        "severity": "Medium",
                        "agent": self.name,
                        "param": f"?author={uid}",
                        "confirmed": True,
                        "poc": f"curl -s '{base}/?author={uid}' | grep 'author-'",
                    })
                    break
            except: pass

        # Try REST API user endpoint
        try:
            r = self.http.get(f"{base}/wp-json/wp/v2/users")
            if r.status_code == 200 and "slug" in r.text[:500]:
                findings.append({
                    "type": "WP REST API User Exposure",
                    "severity": "High",
                    "agent": self.name,
                    "confirmed": True,
                    "poc": f"curl -s '{base}/wp-json/wp/v2/users'",
                })
        except: pass

        # 3. xmlrpc.php checks
        try:
            r = self.http.post(f"{base}/xmlrpc.php", data="<methodCall><methodName>system.listMethods</methodName></methodCall>")
            if r.status_code == 200 and "methodResponse" in r.text:
                findings.append({
                    "type": "WP xmlrpc.php Enabled",
                    "severity": "Medium",
                    "agent": self.name,
                    "confirmed": True,
                    "poc": f"curl -s -X POST '{base}/xmlrpc.php' -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'",
                })
                # Check if pingback is available (SSRF vector)
                if "pingback" in r.text:
                    findings.append({
                        "type": "WP Pingback SSRF via xmlrpc",
                        "severity": "High",
                        "agent": self.name,
                        "confirmed": True,
                    })
        except: pass

        # 4. Plugin enumeration
        plugins_found = []
        for plugin in self.COMMON_PLUGINS[:12]:
            try:
                r = self.http.get(f"{base}/wp-content/plugins/{plugin}/")
                if r.status_code in [200, 301, 302, 403]:
                    plugins_found.append(plugin)
            except: pass

        if plugins_found:
            findings.append({
                "type": "WP Plugins Detected",
                "severity": "Low",
                "agent": self.name,
                "confirmed": len(plugins_found) > 0,
                "analysis": f"Plugins found: {', '.join(plugins_found)}. Check for known CVEs.",
            })

        # 5. Theme enumeration
        themes_found = []
        for theme in self.COMMON_THEMES[:8]:
            try:
                r = self.http.get(f"{base}/wp-content/themes/{theme}/")
                if r.status_code in [200, 301, 302, 403]:
                    themes_found.append(theme)
            except: pass

        if themes_found:
            findings.append({
                "type": "WP Themes Detected",
                "severity": "Info",
                "agent": self.name,
                "analysis": f"Themes found: {', '.join(themes_found)}. Check for known CVEs.",
            })

        # 6. wp-config.php backup variants
        config_variants = ["wp-config.php.bak", "wp-config.php~", "wp-config.php.old", "wp-config.php.save", "wp-config.bak"]
        for cv in config_variants[:4]:
            try:
                r = self.http.get(f"{base}/{cv}")
                if r.status_code == 200 and len(r.text) > 10:
                    findings.append({
                        "type": "WP Config Backup Exposed",
                        "severity": "Critical",
                        "agent": self.name,
                        "path": cv,
                        "confirmed": True,
                        "poc": f"curl -s '{base}/{cv}'",
                    })
                    break
            except: pass

        # 7. wp-admin accessible
        try:
            r = self.http.get(f"{base}/wp-admin/", allow_redirects=False)
            if r.status_code == 200:
                findings.append({
                    "type": "WP Admin Accessible",
                    "severity": "Medium",
                    "agent": self.name,
                    "confirmed": True,
                })
        except: pass

        # 8. Version in generator meta
        try:
            import re
            match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', html)
            if match:
                findings.append({
                    "type": "WP Version Leaked",
                    "severity": "Low",
                    "agent": self.name,
                    "version": match.group(1),
                    "confirmed": True,
                })
        except: pass

        total = len(findings)
        analysis = f"WordPress scan: {total} issues found.\n"
        for f in findings:
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(f.get("severity", ""), "")
            analysis += f"- {icon} [{f['severity']}] {f['type']}\n"

        if total > 0:
            result = self.analyzer.analyze_endpoint(url, analysis=analysis)
        else:
            result = {"analysis": "WordPress scan: no specific vulnerabilities detected."}

        result["real_findings"] = findings
        result["agent"] = self.name
        result["type"] = "WordPress Security"
        result["severity"] = "Critical" if any(f["severity"] == "Critical" for f in findings) else ("High" if any(f["severity"] == "High" for f in findings) else ("Medium" if findings else "Info"))
        return result
