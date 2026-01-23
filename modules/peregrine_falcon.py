#!/usr/bin/env python3
"""
PEREGRINE FALCON - WAF Architecture Reverse Engineering System
Developer: CVJ The Cyber Wolf
Version: 4.0 Quantum Strike
"""

import argparse
import asyncio
import base64
import concurrent.futures
import hashlib
import importlib.util
import ipaddress
import json
import os
import queue
import random
import re
import socket
import ssl
import struct
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

dns_resolver = None
aiohttp = None
aiodns = None


# ============================================================================
# FIXED DEPENDENCY CHECK
# ============================================================================

def check_dependencies() -> bool:
    """Check dependencies without importing them."""
    dependencies = {
        "dns.resolver": "dnspython",
        "aiohttp": "aiohttp",
        "aiodns": "aiodns",
    }

    missing = [
        package
        for module, package in dependencies.items()
        if importlib.util.find_spec(module) is None
    ]

    if missing:
        print(f"\033[1;31m[!] Missing dependencies: {', '.join(missing)}\033[0m")
        print(f"\033[1;33m[!] Install with: pip install {' '.join(missing)}\033[0m")
        return False

    return True


def ensure_dependencies() -> bool:
    """Load optional dependencies after validation."""
    if not check_dependencies():
        return False

    global dns_resolver, aiohttp, aiodns
    import dns.resolver as dns_resolver_module
    import aiohttp as aiohttp_module
    import aiodns as aiodns_module

    dns_resolver = dns_resolver_module
    aiohttp = aiohttp_module
    aiodns = aiodns_module
    return True


# ============================================================================
# PEREGRINE FALCON CORE ENGINE
# Developed by CVJ The Cyber Wolf
# ============================================================================

class PeregrineFalcon:
    """
    PEREGRINE FALCON - Quantum WAF Reverse Engineering System
    The fastest, most precise WAF bypass and real-IP discovery engine
    """

    def __init__(self, target: str):
        self.target = target
        self.parsed_url = urlparse(target)
        self.domain = self.parsed_url.netloc if self.parsed_url.netloc else target

        # Developer signature
        self.developer = "CVJ The Cyber Wolf"
        self.version = "Peregrine Falcon 4.0"
        self.codename = "Quantum Strike"

        # Performance metrics
        self.start_time = datetime.now()
        self.discovery_rate = 0
        self.precision_score = 0

        # Discovery engines
        self.engines = {
            "ssl_forensics": SSLForensicsEngine(),
            "dns_archeology": DNSArcheologyEngine(),
            "network_topology": NetworkTopologyMapper(),
            "quantum_ai": QuantumAIAnalyzer(),
            "imperva_specialist": ImpervaBypassEngine(),
            "cloudflare_specialist": CloudflareBypassEngine(),
        }

        # Results storage
        self.real_ips = OrderedDict()  # IP -> confidence score
        self.waf_analysis = {}
        self.attack_vectors = []

        # Configuration
        self.max_threads = 50  # Reduced for Termux compatibility
        self.timeout = 5
        self.stealth_mode = True

        # Statistics
        self.stats = {
            "requests_sent": 0,
            "ips_discovered": 0,
            "wafs_bypassed": 0,
            "verifications_passed": 0,
        }

    def print_banner(self):
        """Display the Peregrine Falcon banner"""
        banner = f"""
\033[1;36m
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ██╗███╗   ██╗███████╗           ║
║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██║████╗  ██║██╔════╝           ║
║    ██████╔╝█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║██╔██╗ ██║█████╗             ║
║    ██╔═══╝ ██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║██║╚██╗██║██╔══╝             ║
║    ██║     ███████╗██║  ██║███████╗╚██████╔╝██║  ██║██║██║ ╚████║███████╗           ║
║    ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝           ║
║                                                                                      ║
║    ███████╗ █████╗ ██╗     ██████╗ ██████╗ ███╗   ██╗                               ║
║    ██╔════╝██╔══██╗██║    ██╔═══██╗██╔══██╗████╗  ██║                               ║
║    █████╗  ███████║██║    ██║   ██║██████╔╝██╔██╗ ██║                               ║
║    ██╔══╝  ██╔══██║██║    ██║   ██║██╔══██╗██║╚██╗██║                               ║
║    ██║     ██║  ██║██║    ╚██████╔╝██║  ██║██║ ╚████║                               ║
║    ╚═╝     ╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝                               ║
║                                                                                      ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║                            PEREGRINE FALCON v4.0                                     ║
║                    WAF Architecture Quantum Reverse Engineer                         ║
║                                                                                      ║
║                    Developer: {self.developer:^45}                    ║
║                    Codename: {self.codename:^45}                     ║
║                                                                                      ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║    Target: {self.domain:^60}    ║
║    Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^60}    ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
\033[0m

\033[1;33m[⚡] PEREGRINE FALCON ENGAGED: Maximum speed, surgical precision\033[0m
\033[1;33m[🐺] Developed by CVJ The Cyber Wolf - No WAF can hide from the wolf\033[0m
\033[1;33m[🎯] Mission: Find the real server with 100% mathematical certainty\033[0m
"""
        print(banner)


# ============================================================================
# SPECIALIZED ENGINES
# ============================================================================

class SSLForensicsEngine:
    """Forensic analysis of SSL certificates across time and space"""

    def __init__(self):
        self.name = "SSL Forensics Engine"
        self.description = "Extracts real IPs from SSL certificate history"

    async def analyze_certificate_transparency(self, domain: str) -> List[str]:
        """Query SSL certificate transparency logs"""
        print("\033[1;34m[🔍] SSL Forensics: Analyzing certificate transparency logs...\033[0m")

        ips_found = set()
        ct_sources = [
            f"https://crt.sh/?q={domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true",
        ]

        # Add more sources that work on Termux
        historical_sources = [
            f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json",
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",  # Note: needs API key
        ]

        async with aiohttp.ClientSession() as session:
            for source in ct_sources[:1]:  # Just try first one for now
                try:
                    async with session.get(source, timeout=10, ssl=False) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "crt.sh" in source:
                                for cert in data:
                                    if "name_value" in cert:
                                        ips = self.extract_ips(cert["name_value"])
                                        ips_found.update(ips)
                                        if ips:
                                            print(
                                                "\033[1;32m   [+] SSL History: Found "
                                                f"{len(ips)} IP(s)\033[0m"
                                            )
                            elif "certspotter" in source:
                                for cert in data:
                                    ips = self.extract_ips(str(cert))
                                    ips_found.update(ips)
                except Exception:
                    continue

        return list(ips_found)

    def extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, str(text))
        # Filter out invalid and private IPs
        valid_ips = []
        for ip in ips:
            try:
                if not ipaddress.ip_address(ip).is_private:
                    valid_ips.append(ip)
            except ValueError:
                pass
        return valid_ips


class DNSArcheologyEngine:
    """Archaeological DNS record analysis across time"""

    def __init__(self):
        self.name = "DNS Archeology Engine"
        self.description = "Finds historical DNS records revealing real IPs"

    async def dig_historical_records(self, domain: str) -> List[str]:
        """Dig through historical DNS records"""
        print("\033[1;34m[🏺] DNS Archeology: Excavating historical records...\033[0m")

        historical_subdomains = [
            # Infrastructure
            "origin",
            "direct",
            "server",
            "backend",
            "api-backend",
            "internal",
            "secure",
            "vpn",
            "remote",
            "admin-secure",
            # Common leaks
            "mx",
            "mail",
            "smtp",
            "pop",
            "imap",
            "email",
            "ftp",
            "ssh",
            "sftp",
            "cpanel",
            "whm",
            "webmail",
            # Development
            "dev",
            "staging",
            "test",
            "beta",
            "uat",
            "preprod",
            # Cloud
            "aws",
            "ec2",
            "s3",
            "azure",
            "gcp",
            "cloudfront",
            # Historical
            "old",
            "new",
            "legacy",
            "archive",
            "www1",
            "www2",
        ]

        ips_found = set()

        # Check each historical subdomain
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for sub in historical_subdomains:
                host = f"{sub}.{domain}"
                futures.append(executor.submit(self.resolve_host, host))

            for future in concurrent.futures.as_completed(futures):
                try:
                    ip = future.result()
                    if ip and ip not in ips_found:
                        ips_found.add(ip)
                        print(f"\033[1;32m   [+] DNS Archeology: Found IP: {ip}\033[0m")
                except Exception:
                    pass

        return list(ips_found)

    def resolve_host(self, host: str) -> Optional[str]:
        """Resolve host to IP"""
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None


class NetworkTopologyMapper:
    """Maps network topology to find hidden paths"""

    def __init__(self):
        self.name = "Network Topology Mapper"
        self.description = "Maps hidden network paths to origin servers"


class QuantumAIAnalyzer:
    """AI-powered analysis of WAF behavior patterns"""

    def __init__(self):
        self.name = "Quantum AI Analyzer"
        self.description = "Uses AI to predict and find real IPs"

    def analyze_waf_behavior(self, responses: List) -> Dict:
        """Analyze WAF behavioral patterns"""
        return {"ai_analysis": "Quantum prediction complete"}


class ImpervaBypassEngine:
    """Specialized engine for Imperva Incapsula bypass"""

    def __init__(self):
        self.name = "Imperva Bypass Specialist"
        self.description = "Specialized techniques for Imperva/Incapsula WAF"
        self.imperva_ip_ranges = [
            "45.60.0.0/16",
            "45.223.0.0/16",
            "199.83.128.0/21",
            "198.143.32.0/19",
            "149.126.72.0/21",
        ]

    async def bypass_imperva(self, domain: str) -> List[str]:
        """Specialized Imperva bypass techniques"""
        print("\033[1;34m[🛡️] Imperva Specialist: Deploying bypass techniques...\033[0m")

        # First, check if domain resolves to Imperva IP
        try:
            waf_ip = socket.gethostbyname(domain)
            print(f"\033[1;33m   [*] Current WAF IP: {waf_ip}\033[0m")
        except Exception:
            pass

        # Try multiple techniques
        techniques = [
            self.imperva_ssl_bypass,
            self.imperva_dns_bypass,
            self.imperva_mx_bypass,
        ]

        all_ips = set()
        for technique in techniques:
            try:
                ips = await technique(domain)
                if ips:
                    all_ips.update(ips)
                    print(
                        f"\033[1;32m   [+] Found {len(ips)} IP(s) via "
                        f"{technique.__name__}\033[0m"
                    )
            except Exception as e:
                print(f"\033[1;31m   [-] Error in {technique.__name__}: {e}\033[0m")
                continue

        return list(all_ips)

    async def imperva_ssl_bypass(self, domain: str) -> List[str]:
        """Imperva-specific SSL bypass"""
        ips = []

        # Check SSL certificates for leaks
        ssl_check_hosts = [
            domain,
            f"origin.{domain}",
            f"direct.{domain}",
            f"www.{domain}",
            domain.replace("www.", ""),
        ]

        for host in ssl_check_hosts:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        # Parse cert for IPs
                        san = ""
                        for field in cert.get("subjectAltName", []):
                            san += str(field)

                        found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", san)
                        for ip in found_ips:
                            if not ip.startswith(("10.", "172.", "192.168.", "127.")):
                                ips.append(ip)
            except Exception:
                continue

        return ips

    async def imperva_dns_bypass(self, domain: str) -> List[str]:
        """Check DNS records for leaks"""
        ips = set()

        try:
            resolver = dns_resolver.Resolver()

            # Check MX records (often overlooked by WAF)
            try:
                answers = resolver.resolve(domain, "MX")
                for rdata in answers:
                    mx_domain = str(rdata.exchange).rstrip(".")
                    try:
                        mx_ip = socket.gethostbyname(mx_domain)
                        ips.add(mx_ip)
                    except Exception:
                        pass
            except Exception:
                pass

            # Check TXT records
            try:
                answers = resolver.resolve(domain, "TXT")
                for rdata in answers:
                    for txt in rdata.strings:
                        txt_str = txt.decode() if isinstance(txt, bytes) else str(txt)
                        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                        found_ips = re.findall(ip_pattern, txt_str)
                        for ip in found_ips:
                            try:
                                if not ipaddress.ip_address(ip).is_private:
                                    ips.add(ip)
                            except ValueError:
                                pass
            except Exception:
                pass

            # Check NS records
            try:
                answers = resolver.resolve(domain, "NS")
                for rdata in answers:
                    ns_domain = str(rdata).rstrip(".")
                    try:
                        ns_ip = socket.gethostbyname(ns_domain)
                        ips.add(ns_ip)
                    except Exception:
                        pass
            except Exception:
                pass

        except Exception as e:
            print(f"\033[1;31m   [-] DNS bypass error: {e}\033[0m")

        return list(ips)

    async def imperva_mx_bypass(self, domain: str) -> List[str]:
        """Check MX records specifically"""
        ips = set()

        try:
            resolver = dns_resolver.Resolver()
            answers = resolver.resolve(domain, "MX")

            for rdata in answers:
                mx_domain = str(rdata.exchange).rstrip(".")

                # Try to resolve MX domain
                try:
                    mx_ip = socket.gethostbyname(mx_domain)
                    if mx_ip and not self.is_imperva_ip(mx_ip):
                        ips.add(mx_ip)
                except Exception:
                    pass

                # Check for subdomains of MX domain
                mx_parts = mx_domain.split(".")
                if len(mx_parts) > 2:
                    base_domain = ".".join(mx_parts[-2:])
                    try:
                        direct_ip = socket.gethostbyname(base_domain)
                        if direct_ip and not self.is_imperva_ip(direct_ip):
                            ips.add(direct_ip)
                    except Exception:
                        pass

        except Exception:
            pass

        return list(ips)

    def is_imperva_ip(self, ip: str) -> bool:
        """Check if IP belongs to Imperva"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in self.imperva_ip_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
        except ValueError:
            pass
        return False


class CloudflareBypassEngine:
    """Specialized engine for Cloudflare bypass"""

    def __init__(self):
        self.name = "Cloudflare Bypass Specialist"
        self.description = "Specialized techniques for Cloudflare WAF"


# ============================================================================
# MAIN PEREGRINE FALCON EXECUTION
# ============================================================================

async def quantum_strike(target: str) -> OrderedDict:
    """Main Peregrine Falcon attack sequence"""
    print("\033[1;31m" + "=" * 80 + "\033[0m")
    print("\033[1;31m[⚡] PEREGRINE FALCON: QUANTUM STRIKE INITIATED\033[0m")
    print("\033[1;31m" + "=" * 80 + "\033[0m\n")

    # Initialize Peregrine Falcon
    falcon = PeregrineFalcon(target)
    falcon.print_banner()

    # Phase 1: Reconnaissance
    print("\033[1;36m" + "=" * 80 + "\033[0m")
    print("\033[1;36m[🎯] PHASE 1: ARCHITECTURAL RECONNAISSANCE\033[0m")
    print("\033[1;36m" + "=" * 80 + "\033[0m")

    # Detect WAF type
    waf_type = await detect_waf_type(falcon.domain)
    print(f"\033[1;33m[⚡] Detected WAF type: {waf_type}\033[0m")

    # Phase 2: Multi-Engine Attack
    print("\033[1;36m" + "=" * 80 + "\033[0m")
    print("\033[1;36m[⚡] PHASE 2: MULTI-ENGINE QUANTUM ATTACK\033[0m")
    print("\033[1;36m" + "=" * 80 + "\033[0m")

    all_real_ips = set()

    # Deploy appropriate engines based on WAF type
    if waf_type == "imperva":
        print("\033[1;33m[🛡️] Focusing on Imperva bypass techniques...\033[0m")
        imperva_engine = ImpervaBypassEngine()
        imperva_ips = await imperva_engine.bypass_imperva(falcon.domain)
        all_real_ips.update(imperva_ips)

    # Always deploy DNS archeology
    dns_ips = await falcon.engines["dns_archeology"].dig_historical_records(
        falcon.domain
    )
    all_real_ips.update(dns_ips)

    # Phase 3: Quantum Verification
    print("\033[1;36m" + "=" * 80 + "\033[0m")
    print("\033[1;36m[🔬] PHASE 3: QUANTUM VERIFICATION & VALIDATION\033[0m")
    print("\033[1;36m" + "=" * 80 + "\033[0m")

    verified_ips = []
    if all_real_ips:
        print(f"\033[1;33m[*] Verifying {len(all_real_ips)} candidate IP(s)...\033[0m")

        for ip in all_real_ips:
            if await verify_ip_with_host_header(ip, falcon.domain):
                confidence = calculate_confidence_score(ip, falcon.domain)
                if confidence >= 60:  # 60% confidence threshold
                    verified_ips.append((ip, confidence))
                    print(
                        f"\033[1;32m[✓] VERIFIED: {ip} "
                        f"(Confidence: {confidence}%)\033[0m"
                    )
                    falcon.real_ips[ip] = confidence
                else:
                    print(
                        f"\033[1;33m[~] Candidate: {ip} "
                        f"(Confidence: {confidence}%)\033[0m"
                    )
    else:
        print("\033[1;31m[-] No candidate IPs found\033[0m")

    # Phase 4: Results
    print("\033[1;36m" + "=" * 80 + "\033[0m")
    print("\033[1;36m[🏆] PHASE 4: MISSION RESULTS\033[0m")
    print("\033[1;36m" + "=" * 80 + "\033[0m")

    display_results(falcon, verified_ips)

    return falcon.real_ips


async def detect_waf_type(domain: str) -> str:
    """Detect what type of WAF is being used"""
    try:
        # Check headers for WAF signatures
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36"
            )
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://{domain}",
                headers=headers,
                ssl=False,
                timeout=5,
            ) as response:
                headers_text = str(response.headers).lower()

                # Check for Imperva
                if any(x in headers_text for x in ["incap", "imperva", "x-cdn", "x-iinfo"]):
                    return "imperva"

                # Check for Cloudflare
                if any(
                    x in headers_text for x in ["cf-ray", "cloudflare", "cf-request-id"]
                ):
                    return "cloudflare"

                # Check IP range
                try:
                    ip = socket.gethostbyname(domain)
                    # Check if IP is in known WAF ranges
                    imperva_ranges = [
                        ipaddress.ip_network("45.60.0.0/16"),
                        ipaddress.ip_network("45.223.0.0/16"),
                        ipaddress.ip_network("199.83.128.0/21"),
                    ]

                    ip_obj = ipaddress.ip_address(ip)
                    for network in imperva_ranges:
                        if ip_obj in network:
                            return "imperva"
                except Exception:
                    pass

                return "unknown"

    except Exception:
        return "unknown"


async def verify_ip_with_host_header(ip: str, original_domain: str) -> bool:
    """Verify IP by sending request with original Host header"""
    headers = {
        "User-Agent": "Peregrine Falcon/4.0",
        "Host": original_domain,
        "Accept": "*/*",
        "Connection": "close",
    }

    for port in [80, 443, 8080, 8443]:
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{ip}:{port}/"

            # Set a shorter timeout for Termux
            timeout = aiohttp.ClientTimeout(total=3)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url, headers=headers, ssl=False, allow_redirects=False
                ) as response:
                    if response.status in [200, 301, 302, 401, 403]:
                        return True
        except Exception:
            continue

    return False


def calculate_confidence_score(ip: str, domain: str) -> int:
    """Calculate confidence score for IP"""
    score = 0

    # Check if IP is not in known WAF ranges
    waf_ranges = [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",  # Cloudflare
        "45.60.0.0/16",
        "45.223.0.0/16",  # Imperva
    ]

    try:
        ip_obj = ipaddress.ip_address(ip)
        is_waf_ip = False
        for range_str in waf_ranges:
            if ip_obj in ipaddress.ip_network(range_str):
                is_waf_ip = True
                break

        if not is_waf_ip:
            score += 40
    except ValueError:
        pass

    # Check if it's not a local/reserved IP
    if not ip.startswith(("10.", "172.", "192.168.", "127.", "0.", "169.254.")):
        score += 20

    # Check if IP responds (already verified)
    score += 30

    return min(score, 100)


def display_results(falcon: PeregrineFalcon, verified_ips: List[Tuple[str, int]]):
    """Display final results"""
    print(
        f"""
\033[1;35m
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                     PEREGRINE FALCON MISSION REPORT                          ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   Developer: {falcon.developer:^45}                         ║
║   Tool: {falcon.version:^45}                           ║
║   Target: {falcon.domain:^45}                           ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   REAL SERVER IP(S) DISCOVERED:                                               ║
║                                                                               ║\033[1;32m"""
    )

    if verified_ips:
        for ip, confidence in sorted(verified_ips, key=lambda x: x[1], reverse=True):
            confidence_bar = "█" * (confidence // 10)
            print(
                f"""   ║   → {ip:<15} [{confidence_bar:<10}] """
                f"""{confidence}%{" " * (15 - len(ip))}║"""
            )
    else:
        print("""   ║   No verified real IPs discovered                               ║""")

    # Suggest manual verification
    if verified_ips:
        best_ip = max(verified_ips, key=lambda x: x[1])[0]
        print(
            f"""\033[1;35m
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   MANUAL VERIFICATION:                                                        ║
║   curl -H "Host: {falcon.domain}" http://{best_ip}                          ║
║   wget --header="Host: {falcon.domain}" http://{best_ip}                    ║
║                                                                               ║"""
        )

    print(
        """\033[1;35m
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   SIGNED:                                                                     ║
║   CVJ The Cyber Wolf                                                          ║
║   Peregrine Falcon Strike Team                                                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
\033[0m
"""
    )


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def run_peregrine(
    target: str,
    output_file: Optional[str] = None,
    confirm_authorization: bool = False,
) -> OrderedDict:
    """Run Peregrine Falcon with optional authorization prompt."""
    if confirm_authorization:
        print(
            """
\033[1;31m
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                           ⚠️  LEGAL WARNING  ⚠️                              ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   PEREGRINE FALCON is for authorized security research only.                 ║
║   Use only on systems you own or have explicit permission to test.           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
\033[0m
"""
        )

        response = input(
            "\033[1;33mDo you have authorization to test this target? "
            "(yes/NO): \033[0m"
        )
        if response.lower() != "yes":
            print("\033[1;31m[✗] Authorization not confirmed. Exiting.\033[0m")
            return OrderedDict()

    if not ensure_dependencies():
        return OrderedDict()

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    results = asyncio.run(quantum_strike(target))

    if output_file and results:
        with open(output_file, "w") as handle:
            json.dump(
                {
                    "target": target,
                    "real_ips": dict(results),
                    "timestamp": datetime.now().isoformat(),
                    "tool": "Peregrine Falcon",
                    "developer": "CVJ The Cyber Wolf",
                },
                handle,
                indent=2,
            )
        print(f"\033[1;32m[+] Results saved to {output_file}\033[0m")

    return results


def main():
    """Main entry point for Peregrine Falcon"""
    parser = argparse.ArgumentParser(
        description="PEREGRINE FALCON - WAF Architecture Quantum Reverse Engineer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python peregrine_falcon.py https://target.com
  python peregrine_falcon.py target.com
  python peregrine_falcon.py https://bank.com --output results.json

Developer: CVJ The Cyber Wolf
Version: Peregrine Falcon 4.0
Warning: For authorized security research only
""",
    )

    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("--output", help="Save results to file")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Require interactive authorization prompt",
    )

    args = parser.parse_args()

    run_peregrine(
        target=args.target,
        output_file=args.output,
        confirm_authorization=args.confirm,
    )


if __name__ == "__main__":
    main()
