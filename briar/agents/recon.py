"""Reconnaissance Agent — attack surface mapping + port scanning 🔍"""
import re, socket
import requests
from urllib.parse import urlparse, urljoin, parse_qs

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9000, 27017]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9000: "PHP-FPM", 27017: "MongoDB"
}

class ReconAgent:
    """Maps the attack surface of a target"""
    
    def __init__(self, provider="ollama"):
        self.name = "Recon"
    
    def _check_port(self, hostname: str, port: int, timeout: float):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((hostname, port)) == 0:
                return {"port": port, "service": PORT_SERVICES.get(port, "Unknown")}
        except Exception:
            return None
        finally:
            sock.close()
        return None

    def port_scan(self, hostname: str, ports: list = None, timeout: float = 1.0) -> list:
        """Concurrent TCP connect scan (all ports at once — avoids a 30s+ serial wait
        on hosts that drop packets)."""
        if ports is None:
            ports = COMMON_PORTS
        from concurrent.futures import ThreadPoolExecutor
        open_ports = []
        with ThreadPoolExecutor(max_workers=min(24, len(ports))) as pool:
            for res in pool.map(lambda p: self._check_port(hostname, p, timeout), ports):
                if res:
                    open_ports.append(res)
        return sorted(open_ports, key=lambda x: x["port"])
    
    def scan(self, url: str, **kwargs) -> dict:
        """Discover endpoints, technologies, headers, open ports"""
        info = {
            "url": url,
            "agent": self.name,
            "type": "Reconnaissance",
            "severity": "Info",
        }
        
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            info["status"] = resp.status_code
            info["headers"] = dict(resp.headers)
            info["server"] = resp.headers.get("Server", "Unknown")
            
            # Technology detection
            tech = []
            body = resp.text[:5000].lower()
            if "react" in body or "__NEXT_DATA__" in body: tech.append("React/Next.js")
            if "vue" in body or "nuxt" in body: tech.append("Vue/Nuxt")
            if "wp-content" in body: tech.append("WordPress")
            if "laravel" in body: tech.append("Laravel")
            if "django" in body: tech.append("Django")
            if "express" in body: tech.append("Express.js")
            if "nginx" in resp.headers.get("Server",""): tech.append("Nginx")
            if "apache" in resp.headers.get("Server",""): tech.append("Apache")
            info["technologies"] = tech or ["Unknown"]
            
            # Security headers check
            security_headers = {
                "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security"),
                "Content-Security-Policy": resp.headers.get("Content-Security-Policy"),
                "X-Frame-Options": resp.headers.get("X-Frame-Options"),
                "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options"),
            }
            info["security_headers"] = {k: v or "MISSING" for k, v in security_headers.items()}
            
            # Attack-surface mapping. recon's OWN successful fetch (resp) is the
            # reliable source of links; the crawler adds depth when it can reach pages.
            netloc = urlparse(url).netloc
            found = set()
            for href in re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', resp.text, re.I):
                absu = urljoin(url, href.strip()).split("#")[0]
                if absu.startswith("http") and urlparse(absu).netloc == netloc:
                    found.add(absu)
            api_hints = ("/api/", ".php", ".asp", ".aspx", ".jsp", ".do", "/graphql")
            endpoints = [u for u in sorted(found)
                         if ("?" in u) or any(h in u.lower() for h in api_hints)]
            params = set()
            for u in found:
                params.update(parse_qs(urlparse(u).query).keys())
            forms_found = 0
            try:
                from briar.core.crawler import Crawler
                crawl = Crawler(max_pages=12, max_depth=1).crawl(url)
                found.update(crawl.get("urls", []))
                for e in crawl.get("endpoints", []):
                    if e not in endpoints:
                        endpoints.append(e)
                params.update(crawl.get("params", []))
                forms_found = len(crawl.get("forms", []))
                info["forms"] = crawl.get("forms", [])
                info["pages_crawled"] = crawl.get("pages_crawled", 0)
                if crawl.get("errors"):
                    info["crawl_errors"] = crawl["errors"]
            except Exception as e:
                info["crawl_errors"] = [f"crawler: {type(e).__name__}: {e}"]
            info["endpoints_discovered"] = len(found)
            info["urls_sample"] = sorted(found)[:8]
            info["endpoints"] = endpoints[:15]
            info["params_found"] = sorted(params)
            info["forms_found"] = forms_found

            # Self-heal: if the chosen scheme exposed no endpoints, try the other scheme.
            # Its links flow to agents as absolute URLs on the correct scheme.
            if not endpoints:
                other = (url.replace("https://", "http://", 1) if url.startswith("https://")
                         else url.replace("http://", "https://", 1))
                try:
                    r2 = requests.get(other, timeout=8, verify=False, allow_redirects=True)
                    onet = urlparse(other).netloc
                    for href in re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', r2.text, re.I):
                        absu = urljoin(other, href.strip()).split("#")[0]
                        if absu.startswith("http") and urlparse(absu).netloc == onet:
                            found.add(absu)
                            if ("?" in absu) or any(h in absu.lower() for h in api_hints):
                                if absu not in endpoints:
                                    endpoints.append(absu)
                            params.update(parse_qs(urlparse(absu).query).keys())
                    if endpoints:
                        info["scheme_switched_to"] = other
                        info["endpoints_discovered"] = len(found)
                        info["urls_sample"] = sorted(found)[:8]
                        info["endpoints"] = endpoints[:15]
                        info["params_found"] = sorted(params)
                except Exception:
                    pass

            # Port scanning
            hostname = urlparse(url).hostname
            open_ports = []
            if hostname:
                open_ports = self.port_scan(hostname)
            info["open_ports"] = open_ports
            
            info["analysis"] = f"""Reconnaissance complete for {url}

Server: {info['server']}
Technologies: {', '.join(info['technologies'])}
Attack surface: {info['endpoints_discovered']} URLs crawled ({info.get('pages_crawled', 0)} pages), {info.get('forms_found', 0)} forms, {len(info.get('params_found', []))} params

Security Headers:
""" + "\n".join(f"  {k}: {v}" for k, v in info["security_headers"].items()) + f"""

Open Ports ({len(open_ports)}):
""" + ("\n".join(f"  {p['port']}/tcp - {p['service']}" for p in open_ports) if open_ports else "  No open ports detected")
            
        except Exception as e:
            info["error"] = str(e)
            info["analysis"] = f"Recon failed: {e}"
        
        return info
