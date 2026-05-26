#!/usr/bin/env python3
"""
netdiag.py - Network diagnostic utility
Runs a suite of checks: ping, DNS resolution, port scan, HTTP probe

Usage:
  python netdiag.py 8.8.8.8
  python netdiag.py google.com --ports 80 443 22 3306
  python netdiag.py google.com --full
"""

import argparse
import socket
import subprocess
import sys
import time
from datetime import datetime

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}v{RESET} {msg}")
def fail(msg): print(f"  {RED}x{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET} {msg}")
def info(msg): print(f"  {CYAN}->{RESET} {msg}")

def header(title):
    print(f"\n{BOLD}{title}{RESET}")
    print("-" * 50)

def check_dns(host):
    header("DNS Resolution")
    try:
        start = time.perf_counter()
        ip = socket.gethostbyname(host)
        elapsed = (time.perf_counter() - start) * 1000
        ok(f"{host} -> {ip}  ({elapsed:.1f} ms)")
        return ip
    except socket.gaierror as e:
        fail(f"Could not resolve {host}: {e}")
        return None

def check_ping(host, count=4):
    header(f"Ping ({count} packets)")
    param = "-n" if sys.platform == "win32" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, str(count), host],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.splitlines():
            l = line.lower()
            if any(k in l for k in ["packet", "loss", "ms", "avg", "min", "rtt"]):
                info(line.strip())
        if result.returncode == 0:
            ok("Host is reachable")
        else:
            fail("Host did not respond to ping")
    except subprocess.TimeoutExpired:
        fail("Ping timed out")
    except FileNotFoundError:
        warn("ping not available on this system")

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

def check_ports(host, ports):
    header("Port Scan")
    for port in sorted(ports):
        service = COMMON_PORTS.get(port, "unknown")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start = time.perf_counter()
            result = sock.connect_ex((host, port))
            elapsed = (time.perf_counter() - start) * 1000
            sock.close()
            if result == 0:
                ok(f"Port {port:<6} ({service:<12}) OPEN   {elapsed:.0f} ms")
            else:
                fail(f"Port {port:<6} ({service:<12}) CLOSED")
        except socket.error as e:
            fail(f"Port {port:<6} ({service:<12}) ERROR: {e}")

def check_http(host):
    header("HTTP Probe")
    import urllib.request
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            start = time.perf_counter()
            req = urllib.request.urlopen(url, timeout=5)
            elapsed = (time.perf_counter() - start) * 1000
            ok(f"{url}  ->  HTTP {req.status}  ({elapsed:.0f} ms)")
            info(f"Server: {req.headers.get('Server', 'n/a')}")
            info(f"Content-Type: {req.headers.get('Content-Type', 'n/a')}")
            break
        except Exception as e:
            fail(f"{url}  ->  {e}")

def main():
    parser = argparse.ArgumentParser(
        description="netdiag - network diagnostic utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netdiag.py 8.8.8.8
  python netdiag.py google.com --ports 80 443 22
  python netdiag.py github.com --full
        """
    )
    parser.add_argument("host", help="Hostname or IP address to diagnose")
    parser.add_argument("--ports", nargs="+", type=int,
                        help="Ports to scan (default: common ports)")
    parser.add_argument("--full", action="store_true",
                        help="Run all checks including HTTP probe")
    parser.add_argument("--ping-count", type=int, default=4)

    args = parser.parse_args()

    print(f"\n{BOLD}{'='*50}")
    print(f"  netdiag  |  {args.host}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}{RESET}")

    ip = check_dns(args.host)
    target = ip if ip else args.host
    check_ping(target, count=args.ping_count)
    ports = args.ports if args.ports else list(COMMON_PORTS.keys())
    check_ports(target, ports)
    if args.full:
        check_http(args.host)

    print(f"\n{BOLD}Done.{RESET}\n")

if __name__ == "__main__":
    main()
