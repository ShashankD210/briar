"""Briar — Autonomous AI Pentester 🥀"""
__version__ = "0.4.58"

# Scanners talk to hosts with broken TLS on purpose — silence the noise.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
