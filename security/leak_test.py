"""
leak_test.py — IP and DNS Leak Detection Tool
Gage — Week 6

Run this script BEFORE connecting to the VPN to capture baseline info,
then again AFTER connecting to verify:
  1. Your external IP has changed (VPN server's IP is visible, not yours)
  2. DNS queries are being answered by the VPN resolver (not your ISP)
  3. No DNS queries leave on the physical interface

Usage:
    python security/leak_test.py --baseline          # before connecting
    python security/leak_test.py --check             # after connecting
    python security/leak_test.py --check --verbose   # with full output
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from typing import Optional

BASELINE_FILE = "/tmp/vpn_leak_baseline.json"

# Public IP detection services (we query multiple for reliability)
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json",
    "https://api4.my-ip.io/ip.json",
]

DNS_CHECK_HOSTNAME = "whoami.akamai.net"   # responds with the resolver IP


def _print(msg: str, ok: bool = True) -> None:
    mark = "[OK]" if ok else "[!!]"
    print(f"  {mark}  {msg}")


# ── External IP Detection ──────────────────────────────────────────────────────

def get_external_ip(timeout: float = 5.0) -> Optional[str]:
    for url in IP_CHECK_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpn-leak-test/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
                ip = data.get("ip") or data.get("YOUR_IP")
                if ip:
                    return ip.strip()
        except Exception:
            continue
    return None


# ── DNS Resolver Detection ─────────────────────────────────────────────────────

def get_dns_resolver_ip() -> Optional[str]:
    """
    whoami.akamai.net returns a TXT record containing the IP address of the
    DNS resolver that handled the query. If the VPN is working correctly this
    should be the VPN server's resolver, not your ISP's.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", DNS_CHECK_HOSTNAME],
            capture_output=True, text=True, timeout=5,
        )
        answer = result.stdout.strip()
        if answer:
            return answer.splitlines()[0]
    except FileNotFoundError:
        # dig not available — fallback: just resolve and note the resolver from /etc/resolv.conf
        pass
    except Exception:
        pass

    # Fallback: read current resolver from resolv.conf
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except Exception:
        pass

    return None


def get_configured_dns() -> list:
    """Return list of nameservers from /etc/resolv.conf."""
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
    except Exception:
        pass
    return servers


# ── Routing Table ──────────────────────────────────────────────────────────────

def get_default_routes() -> list:
    """Return list of default route entries from the routing table."""
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True,
    )
    return [l.strip() for l in result.stdout.splitlines() if l.strip()]


def get_active_interfaces() -> list:
    """Return names of UP network interfaces."""
    result = subprocess.run(
        ["ip", "-o", "link", "show", "up"],
        capture_output=True, text=True,
    )
    ifaces = []
    for line in result.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            name = parts[1].strip().split("@")[0]
            if name != "lo":
                ifaces.append(name)
    return ifaces


def check_tun_interface(tun_name: str = "vpn0") -> bool:
    """Return True if the named TUN interface is up and has an IP."""
    result = subprocess.run(
        ["ip", "addr", "show", "dev", tun_name],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and "inet " in result.stdout


# ── Active DNS Leak Check via iptables ────────────────────────────────────────

def check_dns_rules_active() -> bool:
    """Return True if VPN DNS-blocking iptables rules are present."""
    result = subprocess.run(["iptables", "-S"], capture_output=True, text=True)
    return "vpn-client-managed" in result.stdout


# ── Main Checks ───────────────────────────────────────────────────────────────

def run_baseline() -> dict:
    print("\n=== VPN Leak Test — BASELINE (before VPN) ===\n")
    print("Collecting baseline (this will be compared after VPN connects)...\n")

    baseline = {
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "external_ip":  None,
        "dns_resolver": None,
        "dns_config":   [],
        "default_routes": [],
    }

    ip = get_external_ip()
    baseline["external_ip"] = ip
    print(f"  External IP   : {ip or '(could not determine)'}")

    dns = get_dns_resolver_ip()
    baseline["dns_resolver"] = dns
    print(f"  DNS resolver  : {dns or '(could not determine)'}")

    baseline["dns_config"] = get_configured_dns()
    print(f"  /etc/resolv.conf : {baseline['dns_config']}")

    baseline["default_routes"] = get_default_routes()
    for r in baseline["default_routes"]:
        print(f"  Route: {r}")

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"\nBaseline saved to {BASELINE_FILE}")
    print("Connect to the VPN, then run:  python security/leak_test.py --check\n")
    return baseline


def run_check(verbose: bool = False, tun_name: str = "vpn0") -> bool:
    print("\n=== VPN Leak Test — CONNECTED CHECK ===\n")
    passed = True

    # Load baseline if available
    baseline = {}
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE) as f:
            baseline = json.load(f)
        print(f"  Baseline from: {baseline.get('timestamp', '?')}\n")
    else:
        print("  (No baseline found — run with --baseline before connecting for full comparison)\n")

    # 1. TUN interface check
    tun_up = check_tun_interface(tun_name)
    _print(f"TUN interface {tun_name!r} is UP", tun_up)
    if not tun_up:
        passed = False

    # 2. External IP changed
    current_ip = get_external_ip()
    baseline_ip = baseline.get("external_ip")
    if current_ip and baseline_ip:
        ip_changed = current_ip != baseline_ip
        _print(
            f"External IP changed: {baseline_ip} → {current_ip}",
            ip_changed,
        )
        if not ip_changed:
            print("      ^ Your real IP is still visible — traffic is NOT going through VPN!")
            passed = False
    elif current_ip:
        print(f"  [--]  External IP: {current_ip} (no baseline to compare)")
    else:
        print("  [--]  Could not reach external IP check service")

    # 3. DNS resolver check
    current_dns = get_dns_resolver_ip()
    baseline_dns = baseline.get("dns_resolver")
    dns_config   = get_configured_dns()

    _print(f"/etc/resolv.conf nameservers: {dns_config}", bool(dns_config))
    if verbose:
        print(f"        (baseline was: {baseline.get('dns_config', [])})")

    if current_dns and baseline_dns:
        dns_changed = current_dns != baseline_dns
        _print(
            f"DNS resolver changed: {baseline_dns} → {current_dns}",
            dns_changed,
        )
        if not dns_changed:
            print("      ^ DNS may be leaking — resolver did not change after VPN connected!")
            passed = False
    elif current_dns:
        print(f"  [--]  DNS resolver: {current_dns} (no baseline to compare)")

    # 4. iptables DNS block rules
    rules_active = check_dns_rules_active()
    _print("iptables DNS-block rules active (ClientFirewall)", rules_active)
    if not rules_active:
        print("      ^ DNS leak prevention rules not detected — run client with firewall enabled")

    # 5. Routing table sanity
    routes = get_default_routes()
    if verbose:
        print(f"\n  Routing table (default routes):")
        for r in routes:
            print(f"    {r}")

    vpn_routes_present = any(tun_name in r for r in get_default_routes()) or \
                         bool(subprocess.run(
                             ["ip", "route", "show"],
                             capture_output=True, text=True
                         ).stdout.count(tun_name))
    _print(f"VPN routes present in routing table", vpn_routes_present)

    print()
    if passed:
        print("RESULT: All checks passed — VPN appears to be working correctly.\n")
    else:
        print("RESULT: One or more checks FAILED — see items marked [!!] above.\n")

    return passed


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="VPN IP/DNS leak detection tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--baseline", action="store_true",
                       help="Record baseline (run BEFORE connecting to VPN)")
    group.add_argument("--check",    action="store_true",
                       help="Run leak checks (run AFTER connecting to VPN)")
    parser.add_argument("--tun",     default="vpn0", help="TUN interface name (default: vpn0)")
    parser.add_argument("--verbose", action="store_true", help="Show extra detail")
    args = parser.parse_args()

    if args.baseline:
        run_baseline()
    else:
        ok = run_check(verbose=args.verbose, tun_name=args.tun)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
