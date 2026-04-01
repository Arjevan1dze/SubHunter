#!/usr/bin/env python3

"""
╔══════════════════════════════════════════════════════════════╗
║              0day Recon Framework v1.0                     ║
║   Subfinder + Amass + Assetfinder + crt.sh + HTTPX           ║
╚══════════════════════════════════════════════════════════════╝
"""

import subprocess
import sys
import os
import json
import re
import requests
import time
from datetime import datetime

# ─── Colors ───────────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}
  ███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██╔════╝██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ╚════██║██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RESET}
  {BOLD}SubHunter{RESET} {YELLOW}v1.0{RESET}
  {BLUE}Subfinder + Amass + Assetfinder + crt.sh + HTTPX{RESET}
  ─────────────────────────────────────────────
""")

def info(msg):
    print(f"{BLUE}[*]{RESET} {msg}")

def success(msg):
    print(f"{GREEN}[+]{RESET} {msg}")

def warn(msg):
    print(f"{YELLOW}[!]{RESET} {msg}")

def error(msg):
    print(f"{RED}[✗]{RESET} {msg}")

def phase(num, name):
    print(f"\n{CYAN}{BOLD}{'─'*55}{RESET}")
    print(f"{CYAN}{BOLD}  PHASE {num}: {name}{RESET}")
    print(f"{CYAN}{BOLD}{'─'*55}{RESET}\n")

# ─── Helpers ──────────────────────────────────────────────────

def clean_domain(raw: str) -> str:
    """
    https://example.com  →  example.com
    http://example.com/  →  example.com
    example.com          →  example.com
    """
    domain = raw.strip()
    domain = re.sub(r'^https?://', '', domain)   # strip scheme
    domain = domain.rstrip('/')                   # strip trailing slash
    domain = domain.split('/')[0]                 # strip any path
    domain = domain.split('?')[0]                 # strip query string
    return domain.lower()

def tool_exists(tool: str) -> bool:
    return subprocess.run(
        ['which', tool],
        capture_output=True
    ).returncode == 0

def check_tools():
    required = ['subfinder', 'httpx']
    optional = ['amass', 'assetfinder']
    missing_required = []
    missing_optional = []

    for t in required:
        if not tool_exists(t):
            missing_required.append(t)
    for t in optional:
        if not tool_exists(t):
            missing_optional.append(t)

    if missing_required:
        error(f"Required tools not found: {', '.join(missing_required)}")
        error("Install them and try again.")
        sys.exit(1)
    if missing_optional:
        warn(f"Optional tools not found (will be skipped): {', '.join(missing_optional)}")

    return missing_optional

def run_cmd(cmd: list, desc: str) -> str:
    """Run a command, stream output, return stdout as string."""
    info(f"Running: {BOLD}{' '.join(cmd)}{RESET}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        if result.stdout.strip():
            count = len(result.stdout.strip().splitlines())
            success(f"{desc} → {GREEN}{count}{RESET} results")
        else:
            warn(f"{desc} → 0 results")
        return result.stdout.strip()
    except FileNotFoundError:
        warn(f"{desc} → tool not available, skipping")
        return ""

def append_to_file(filepath: str, content: str):
    if content:
        with open(filepath, 'a') as f:
            f.write(content + '\n')

def read_lines(filepath: str) -> list:
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return [l.strip() for l in f if l.strip()]

def dedup_file(filepath: str):
    """Sort and deduplicate a file in-place."""
    lines = read_lines(filepath)
    unique = sorted(set(lines))
    with open(filepath, 'w') as f:
        f.write('\n'.join(unique) + '\n')
    return len(unique)

# ─── crt.sh ───────────────────────────────────────────────────

def crtsh_enum(domain: str) -> list:
    """Query crt.sh for certificate transparency subdomains."""
    info("Querying crt.sh (certificate transparency)...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=30, headers={'User-Agent': 'recon-script/1.0'})
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            names = entry.get('name_value', '')
            for name in names.split('\n'):
                name = name.strip().lower()
                # filter wildcards and unrelated domains
                if name.startswith('*'):
                    name = name[2:]
                if name.endswith(f'.{domain}') or name == domain:
                    subdomains.add(name)
        success(f"crt.sh → {GREEN}{len(subdomains)}{RESET} results")
        return list(subdomains)
    except requests.exceptions.Timeout:
        warn("crt.sh timed out, skipping")
        return []
    except requests.exceptions.JSONDecodeError:
        warn("crt.sh returned invalid JSON, skipping")
        return []
    except Exception as e:
        warn(f"crt.sh error: {e}")
        return []

# ─── PHASE 1: Enumeration ─────────────────────────────────────

def phase1_enum(domain: str, output_dir: str, missing_optional: list) -> str:
    phase(1, "SUBDOMAIN ENUMERATION")
    unfiltered = os.path.join(output_dir, 'Unfiltered.txt')

    # Clear any previous run
    if os.path.exists(unfiltered):
        os.remove(unfiltered)

    # ── Subfinder ──────────────────────────────────────────────
    info("Starting subfinder (passive + all sources, recursive)...")
    sf_out = run_cmd(
        ['subfinder', '-d', domain, '-all', '-recursive', '-silent'],
        "Subfinder"
    )
    append_to_file(unfiltered, sf_out)

    # ── Amass ──────────────────────────────────────────────────
    if 'amass' not in missing_optional:
        amass_out = run_cmd(
            ['amass', 'enum', '-passive', '-d', domain],
            "Amass"
        )
        append_to_file(unfiltered, amass_out)
    else:
        warn("amass not found — skipping")

    # ── Assetfinder ────────────────────────────────────────────
    if 'assetfinder' not in missing_optional:
        af_out = run_cmd(
            ['assetfinder', '--subs-only', domain],
            "Assetfinder"
        )
        # assetfinder sometimes returns parent domains too, filter
        filtered_af = '\n'.join(
            l for l in af_out.splitlines()
            if l.strip().endswith(f'.{domain}') or l.strip() == domain
        )
        append_to_file(unfiltered, filtered_af)
    else:
        warn("assetfinder not found — skipping")

    # ── crt.sh ─────────────────────────────────────────────────
    crt_results = crtsh_enum(domain)
    if crt_results:
        append_to_file(unfiltered, '\n'.join(crt_results))

    # ── Dedup ──────────────────────────────────────────────────
    if os.path.exists(unfiltered):
        count = dedup_file(unfiltered)
        success(f"Unfiltered.txt → {GREEN}{count}{RESET} unique subdomains after dedup")
    else:
        error("No subdomains collected. Exiting.")
        sys.exit(1)

    return unfiltered

# ─── PHASE 2: Filtering with HTTPX ───────────────────────────

def phase2_httpx(unfiltered: str, output_dir: str):
    phase(2, "FILTERING WITH HTTPX (Live Host Detection)")

    alive = os.path.join(output_dir, 'Alive.txt')
    info("Running httpx — this may take a while depending on subdomain count...")
    info("Detecting: status codes, titles, web technologies, CDN, IP")

    httpx_cmd = [
        'httpx',
        '-l', unfiltered,
        '-o', alive,
        '-title',           # grab page title
        '-tech-detect',     # detect technologies
        '-status-code',     # show status code
        '-mc', '200,201,301,302,403,401,500',  # match these codes
        '-silent',
        '-follow-redirects',
        '-threads', '50',
        '-timeout', '10',
        '-retries', '2',
    ]

    info(f"Running: {BOLD}{' '.join(httpx_cmd)}{RESET}")

    try:
        proc = subprocess.Popen(
            httpx_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        alive_count = 0
        for line in proc.stdout:
            line = line.strip()
            if line:
                print(f"  {GREEN}→{RESET} {line}")
                alive_count += 1

        proc.wait()

        print()
        success(f"httpx done → {GREEN}{alive_count}{RESET} live hosts written to Alive.txt")

    except FileNotFoundError:
        error("httpx not found!")
        sys.exit(1)

    # ── Remove Unfiltered.txt ──────────────────────────────────
    if os.path.exists(unfiltered):
        os.remove(unfiltered)
        info("Cleaned up Unfiltered.txt (no longer needed)")

# ─── Summary ──────────────────────────────────────────────────

def print_summary(domain: str, output_dir: str, start_time: float):
    elapsed = time.time() - start_time
    alive = os.path.join(output_dir, 'Alive.txt')
    alive_count = len(read_lines(alive)) if os.path.exists(alive) else 0

    print(f"""
{CYAN}{BOLD}{'═'*55}
  RECON COMPLETE
{'═'*55}{RESET}

  {BOLD}Target:{RESET}       {domain}
  {BOLD}Output dir:{RESET}   {output_dir}
  {BOLD}Live hosts:{RESET}   {GREEN}{alive_count}{RESET}
  {BOLD}Time elapsed:{RESET} {elapsed:.1f}s

  {BOLD}Files:{RESET}
  {GREEN}✓{RESET} {alive}

{CYAN}{BOLD}{'═'*55}{RESET}
""")

# ─── Entry Point ──────────────────────────────────────────────

def main():
    banner()
    start_time = time.time()

    # ── Get domain from user ───────────────────────────────────
    try:
        raw_input = input(f"{BOLD}[?] Enter target domain: {RESET}").strip()
    except KeyboardInterrupt:
        print()
        error("Aborted.")
        sys.exit(0)

    if not raw_input:
        error("No domain provided.")
        sys.exit(1)

    domain = clean_domain(raw_input)

    if not domain or '.' not in domain:
        error(f"Invalid domain: '{domain}'")
        sys.exit(1)

    success(f"Target domain set → {BOLD}{domain}{RESET}")

    # ── Output directory ───────────────────────────────────────
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f"recon_{domain}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    info(f"Output directory: {BOLD}{output_dir}{RESET}")

    # ── Check required tools ───────────────────────────────────
    missing_optional = check_tools()

    # ── Phase 1: Enum ──────────────────────────────────────────
    unfiltered = phase1_enum(domain, output_dir, missing_optional)

    # ── Phase 2: HTTPX ─────────────────────────────────────────
    phase2_httpx(unfiltered, output_dir)

    # ── Summary ────────────────────────────────────────────────
    print_summary(domain, output_dir, start_time)


if __name__ == '__main__':
    main()
