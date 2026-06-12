# Network Diagnostics Tool

A Python command-line network diagnostic utility — run DNS lookups, ping tests, port scans, and HTTP probes against any host or IP in one command. No need to remember individual `ping`, `nmap`, or `curl` flags.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **DNS resolution** — resolve hostnames to IPs with response time
- **Ping test** — ICMP packet loss summary with configurable count and timeout
- **Port scanner** — check common services (SSH 22, HTTP 80, HTTPS 443, MySQL 3306, Redis 6379, etc.)
- **HTTP probe** — check response code and server headers
- **Export results** to a timestamped text file with `--export`
- Color-coded output: green = open/reachable, red = closed/failed
- No external dependencies — pure Python standard library (`socket`, `subprocess`, `urllib`)

## Requirements

- Python 3.7+
- No `pip install` needed

## Installation

```bash
git clone https://github.com/jonatakuzi/network-diagnostics.git
cd network-diagnostics
```

## Usage

### Basic scan (DNS + ping + common ports)
```bash
python netdiag.py google.com
python netdiag.py 192.168.1.1
```
```
[ DNS ]  google.com → 142.250.80.46  (2ms)
[ PING ] 4/4 packets received, 0% loss, avg 11ms
[ PORTS ]
  22  SSH     closed
  80  HTTP    open
  443 HTTPS   open
```

### Scan specific ports
```bash
python netdiag.py github.com --ports 22 80 443 9418
```

### HTTP probe
```bash
python netdiag.py example.com --http
```

### Custom ping count and timeout
```bash
python netdiag.py 10.0.0.5 --count 10 --timeout 2
```

### Export results to file
```bash
python netdiag.py example.com --export
```
Saves to `netdiag_example.com_20241115_143201.txt`

## Tech Stack

- Python 3.7+
- Standard library: `socket`, `subprocess`, `urllib`, `argparse`, `datetime`
