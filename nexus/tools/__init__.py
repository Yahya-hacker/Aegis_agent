"""
Nexus v2.0 - Tool Layer
=======================

Wrappers for Standard Kali Linux Tools.
"""

# Recon Wrappers
from nexus.tools.recon.nmap import run_nmap, NmapResult
from nexus.tools.recon.subfinder import run_subfinder
from nexus.tools.recon.httpx import run_httpx
from nexus.tools.recon.katana import run_katana, CrawlResult
from nexus.tools.recon.crawler import crawl_website # keeping legacy/simple one too if needed

# Exploit Wrappers
from nexus.tools.exploit.nuclei import run_nuclei, NucleiResult
from nexus.tools.exploit.sqlmap import run_sqlmap, SQLMapResult
from nexus.tools.exploit.commix import run_commix, CommixResult

# Auth Tools (Custom)
from nexus.tools.auth.jwt_tool import scan_jwt
from nexus.tools.auth.oauth import scan_oauth
from nexus.tools.auth.session import scan_session

# Fuzzers (Custom + Wrapper)
from nexus.tools.fuzzers.graphql import scan_graphql
from nexus.tools.fuzzers.race import test_race
from nexus.tools.fuzzers.ffuf import run_ffuf, FfufResult
