"""
netdiag.py - Python CLI network diagnostic tool. No external dependencies.

Runs a suite of network checks against any hostname or IP address:
  DNS resolution, ICMP ping, TCP port scanning, HTTP probing.
  Results can be exported to a timestamped text file with --export.

Usage:
    python netdiag.py google.com
    python netdiag.py github.com --ports 22 80 443
    python netdiag.py 10.0.0.5 --http --export
    python netdiag.py example.com --count 10 --timeout 2

All checks use Python stdlib only (socket, subprocess, urllib, argparse).
"""

import argparse
import datetime
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

COLORS_ENABLED = sys.stdout.isatty()


def green(text: str) -> str:
    """Wrap text in green ANSI color if terminal supports it."""
    return f"{GREEN}{text}{RESET}" if COLORS_ENABLED else text


def red(text: str) -> str:
    """Wrap text in red ANSI color if terminal supports it."""
    return f"{RED}{text}{RESET}" if COLORS_ENABLED else text


def yellow(text: str) -> str:
    """Wrap text in yellow ANSI color if terminal supports it."""
    return f"{YELLOW}{text}{RESET}" if COLORS_ENABLED else text


def cyan(text: str) -> str:
    """Wrap text in cyan ANSI color if terminal supports it."""
    return f"{CYAN}{text}{RESET}" if COLORS_ENABLED else text


# ---------------------------------------------------------------------------
# Common service ports
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_dns(host: str) -> dict:
    """
    Resolve a hostname to its IP address(es) and measure lookup time.

    Uses socket.getaddrinfo() which returns all address families (IPv4 and IPv6).
    DNS resolution time matters for diagnosing slow website loads - a slow
    DNS server can add hundreds of milliseconds before a connection even starts.

    Returns a dict with 'host', 'addresses', 'elapsed_ms', and 'error'.
    """
    start = time.time()
    try:
        results = socket.getaddrinfo(host, None)
        elapsed_ms = (time.time() - start) * 1000
        addresses = list({r[4][0] for r in results})
        return {"host": host, "addresses": addresses, "elapsed_ms": round(elapsed_ms, 1), "error": None}
    except socket.gaierror as e:
        elapsed_ms = (time.time() - start) * 1000
        return {"host": host, "addresses": [], "elapsed_ms": round(elapsed_ms, 1), "error": str(e)}


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

def ping_host(host: str, count: int = 4) -> dict:
    """
    Send ICMP ping packets to a host and summarize the results.

    Uses the system's ping command (works on Windows, macOS, and Linux).
    We detect the OS to pass the correct flags: -n on Windows, -c elsewhere.
    Pinging is the fastest way to verify basic IP reachability and round-trip
    latency before investigating higher-level protocol issues.

    Returns a dict with 'reachable', 'packet_loss_pct', 'avg_ms', and 'raw'.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * 3 + 5,
        )
        output = result.stdout + result.stderr
        reachable = result.returncode == 0

        # Extract average RTT from ping output (varies by OS)
        avg_ms = None
        for line in output.splitlines():
            line_lower = line.lower()
            if "avg" in line_lower or "average" in line_lower:
                parts = line.replace("=", "/").split("/")
                for part in parts:
                    try:
                        val = float(part.strip().split()[0])
                        if 0 < val < 100000:
                            avg_ms = round(val, 1)
                            break
                    except (ValueError, IndexError):
                        continue

        # Extract packet loss percentage
        loss_pct = None
        for line in output.splitlines():
            if "%" in line and ("loss" in line.lower() or "packet" in line.lower()):
                for token in line.split():
                    if "%" in token:
                        try:
                            loss_pct = float(token.replace("%", "").replace(",", ""))
                            break
                        except ValueError:
                            continue

        return {
            "reachable": reachable,
            "packet_loss_pct": loss_pct,
            "avg_ms": avg_ms,
            "raw": output.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"reachable": False, "packet_loss_pct": 100, "avg_ms": None, "raw": "Ping timed out."}
    except FileNotFoundError:
        return {"reachable": False, "packet_loss_pct": None, "avg_ms": None, "raw": "ping command not found."}


# ---------------------------------------------------------------------------
# Port scanner
# ---------------------------------------------------------------------------

def scan_port(host: str, port: int, timeout: float = 1.5) -> dict:
    """
    Attempt a TCP connection to a single host:port and report open/closed.

    TCP connect scanning works by completing the full three-way handshake.
    If the connection succeeds, the port is open. If it's refused or times
    out, the port is closed or filtered. This is the most reliable scanning
    method but it leaves a log entry on the target server.

    Returns a dict with 'port', 'service', 'open', and 'elapsed_ms'.
    """
    service = COMMON_PORTS.get(port, "unknown")
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.time() - start) * 1000
            return {"port": port, "service": service, "open": True, "elapsed_ms": round(elapsed_ms, 1)}
    except (socket.timeout, ConnectionRefusedError, OSError):
        elapsed_ms = (time.time() - start) * 1000
        return {"port": port, "service": service, "open": False, "elapsed_ms": round(elapsed_ms, 1)}


def scan_ports(host: str, ports: list[int], timeout: float = 1.5) -> list[dict]:
    """
    Scan a list of TCP ports on a host and return results for each.
    Ports are scanned sequentially; results are sorted by port number.
    """
    return [scan_port(host, p, timeout) for p in sorted(ports)]


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------

def probe_http(host: str, timeout: float = 5.0) -> dict:
    """
    Send an HTTP GET request to the host and capture the response metadata.

    We try HTTPS first (port 443), then fall back to plain HTTP (port 80).
    This reveals the HTTP status code, server software, and response time -
    all useful for diagnosing web application issues.

    Returns a dict with 'url', 'status_code', 'server', 'elapsed_ms', 'error'.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        start = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netdiag/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed_ms = (time.time() - start) * 1000
                return {
                    "url": url,
                    "status_code": resp.status,
                    "server": resp.headers.get("Server", "unknown"),
                    "content_type": resp.headers.get("Content-Type", "unknown"),
                    "elapsed_ms": round(elapsed_ms, 1),
                    "error": None,
                }
        except urllib.error.HTTPError as e:
            elapsed_ms = (time.time() - start) * 1000
            return {
                "url": url,
                "status_code": e.code,
                "server": e.headers.get("Server", "unknown"),
                "content_type": None,
                "elapsed_ms": round(elapsed_ms, 1),
                "error": str(e.reason),
            }
        except Exception:
            continue

    return {"url": f"http://{host}", "status_code": None, "server": None,
            "content_type": None, "elapsed_ms": None, "error": "Connection failed"}


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a section header with cyan color."""
    print(f"\n{cyan(title)}")
    print("-" * 50)


def format_results(host: str, dns: dict, ping: dict, ports: list[dict], http: dict | None) -> str:
    """
    Format all scan results into a plain-text report string.
    Used for both console output and --export file writing.
    """
    lines = []
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(f"Network Diagnostic Report")
    lines.append(f"Generated: {ts}")
    lines.append(f"Target:    {host}")
    lines.append("")

    # DNS
    lines.append("--- DNS Resolution ---")
    if dns["error"]:
        lines.append(f"FAIL  {dns['error']}")
    else:
        for addr in dns["addresses"]:
            lines.append(f"OK    {dns['host']} -> {addr}  ({dns['elapsed_ms']} ms)")
    lines.append("")

    # Ping
    lines.append("--- Ping ---")
    if ping["reachable"]:
        loss = f"{ping['packet_loss_pct']}% loss" if ping["packet_loss_pct"] is not None else ""
        avg = f"avg {ping['avg_ms']} ms" if ping["avg_ms"] else ""
        lines.append(f"OK    Host reachable  {avg}  {loss}".strip())
    else:
        lines.append("FAIL  Host unreachable or all packets lost")
    lines.append("")

    # Ports
    lines.append("--- Port Scan ---")
    for p in ports:
        status = "OPEN  " if p["open"] else "CLOSED"
        lines.append(f"{status}  {p['port']:>5}/{p['service']:<14} {p['elapsed_ms']} ms")
    lines.append("")

    # HTTP
    if http:
        lines.append("--- HTTP Probe ---")
        if http["error"] and http["status_code"] is None:
            lines.append(f"FAIL  {http['error']}")
        else:
            lines.append(f"URL:     {http['url']}")
            lines.append(f"Status:  {http['status_code']}")
            lines.append(f"Server:  {http['server']}")
            lines.append(f"Time:    {http['elapsed_ms']} ms")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_diagnostics(host: str, ports: list[int], ping_count: int,
                    timeout: float, include_http: bool, export: bool) -> None:
    """
    Orchestrate all diagnostic checks and print results to the console.
    If --export is set, also write a plain-text report to disk.

    This function ties everything together: it calls each check in sequence,
    prints color-coded results as they come in, and optionally saves a report.
    """
    print(f"\nRunning diagnostics for: {cyan(host)}")
    print("=" * 50)

    # DNS
    print_section("DNS Resolution")
    dns = resolve_dns(host)
    if dns["error"]:
        print(f"  {red('FAIL')}  {dns['error']}")
        resolved_host = host
    else:
        for addr in dns["addresses"]:
            print(f"  {green('OK')}    {dns['host']} -> {addr}  ({dns['elapsed_ms']} ms)")
        resolved_host = dns["addresses"][0] if dns["addresses"] else host

    # Ping
    print_section("Ping Test")
    ping = ping_host(resolved_host, count=ping_count)
    if ping["reachable"]:
        loss = f"{ping['packet_loss_pct']}% packet loss" if ping["packet_loss_pct"] is not None else ""
        avg = f"avg {ping['avg_ms']} ms" if ping["avg_ms"] else ""
        print(f"  {green('OK')}    Host reachable  {avg}  {loss}".strip())
    else:
        print(f"  {red('FAIL')}  Host unreachable or all packets lost")

    # Port scan
    print_section("Port Scan")
    port_results = scan_ports(resolved_host, ports, timeout=timeout)
    for p in port_results:
        label = f"{p['port']:>5}/{p['service']:<14}"
        if p["open"]:
            print(f"  {green('OPEN')}   {label}  {p['elapsed_ms']} ms")
        else:
            print(f"  {red('CLOSED')} {label}  {p['elapsed_ms']} ms")

    # HTTP
    http_result = None
    if include_http:
        print_section("HTTP Probe")
        http_result = probe_http(host, timeout=timeout)
        if http_result["status_code"] is not None:
            code = http_result["status_code"]
            color_fn = green if code < 400 else red
            print(f"  {color_fn(str(code))}  {http_result['url']}")
            print(f"  Server: {http_result['server']}")
            print(f"  Time:   {http_result['elapsed_ms']} ms")
        else:
            print(f"  {red('FAIL')}  {http_result['error']}")

    print()

    # Export
    if export:
        report = format_results(host, dns, ping, port_results, http_result)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"netdiag_{host.replace('.', '_')}_{ts}.txt"
        with open(filename, "w") as f:
            f.write(report)
        print(f"{green('Report saved:')} {filename}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Build the CLI argument parser.
    All diagnostic options have sensible defaults so a basic run only needs a hostname.
    """
    parser = argparse.ArgumentParser(
        prog="netdiag",
        description="Network diagnostic tool: DNS, ping, port scan, HTTP probe.",
    )
    parser.add_argument("host", help="Hostname or IP address to diagnose")
    parser.add_argument(
        "--ports", nargs="+", type=int,
        default=list(COMMON_PORTS.keys()),
        help="TCP ports to scan (default: common service ports)",
    )
    parser.add_argument(
        "--count", type=int, default=4,
        help="Number of ping packets to send (default: 4)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.5,
        help="Socket timeout in seconds for port/HTTP checks (default: 1.5)",
    )
    parser.add_argument(
        "--http", action="store_true",
        help="Run an HTTP/HTTPS probe against the host",
    )
    parser.add_argument(
        "--export", action="store_true",
        help="Save results to a timestamped text file",
    )
    return parser


def main():
    """Parse arguments and run the full diagnostic suite."""
    parser = build_parser()
    args = parser.parse_args()
    run_diagnostics(
        host=args.host,
        ports=args.ports,
        ping_count=args.count,
        timeout=args.timeout,
        include_http=args.http,
        export=args.export,
    )


if __name__ == "__main__":
    main()
