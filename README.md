# Network Diagnostics Tool

A Python command-line network diagnostic utility that runs a suite of checks against any host or IP — DNS resolution, ping, port scanning, and HTTP probing. Built for quick troubleshooting without needing to remember individual `ping`, `nmap`, or `curl` commands.

## Features

- **DNS resolution** with response time
- **Ping test** with packet loss summary
- **Port scanner** across common services (SSH, HTTP, MySQL, Redis, etc.)
- **HTTP probe** — checks response code and server headers
- Color-coded output (green = open/reachable, red = closed/failed)
- No external dependencies — pure Python standard library

## Requirements

- Python 3.7+
- No pip installs needed

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

### Scan specific ports
```bash
python netdiag.py github.com --ports 22 80 443
python netdiag.py 10.0.0.5 --ports 3306 5432 6379
```

### Full scan including HTTP probe
```bash
python netdiag.py example.com --full
```

## Example Output

```
==================================================
  netdiag  |  github.com
  2025-05-20 11:32:04
==================================================

DNS Resolution
--------------------------------------------------
  v github.com -> 140.82.114.4  (12.3 ms)

Ping (4 packets)
--------------------------------------------------
  -> 4 packets transmitted, 4 received, 0% packet loss
  v Host is reachable

Port Scan
--------------------------------------------------
  v Port 22     (SSH         ) OPEN    11 ms
  v Port 80     (HTTP        ) OPEN    10 ms
  v Port 443    (HTTPS       ) OPEN    10 ms
  x Port 3306   (MySQL       ) CLOSED

Done.
```

## Ports Scanned by Default

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 3306 | MySQL |
| 25 | SMTP | 3389 | RDP |
| 53 | DNS | 5432 | PostgreSQL |
| 80 | HTTP | 6379 | Redis |
| 110 | POP3 | 8080 | HTTP-Alt |
| 143 | IMAP | 27017 | MongoDB |

## Project Structure

```
network-diagnostics/
├── netdiag.py   # Main diagnostic script
└── README.md
```

## Use Cases

- Quickly check if a server is reachable and which services are exposed
- Troubleshoot connectivity issues during deployments
- Verify firewall rules are working as expected
- Pre-flight check before connecting to a remote database or API
