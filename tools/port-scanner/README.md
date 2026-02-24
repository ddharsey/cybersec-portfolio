# Port Scanner

A multi-threaded TCP port scanner with service identification and banner grabbing.

## Features

- **Multi-threaded scanning** — configurable thread count for fast scanning
- **Service identification** — maps open ports to known services (SSH, HTTP, RDP, SMB, etc.)
- **Banner grabbing** — attempts to retrieve service banners from open ports
- **Flexible port input** — single ports, comma-separated lists, or ranges
- **Clean CLI output** — formatted table with scan summary and timing

## Usage

```bash
# Scan default ports (1-1024) on a target
python port_scanner.py -t 192.168.1.1

# Scan specific ports
python port_scanner.py -t 10.0.0.1 -p 22,80,443,3389

# Scan a range with more threads
python port_scanner.py -t scanme.nmap.org -p 1-1000 -T 200

# Full range scan with custom timeout
python port_scanner.py -t 192.168.1.1 -p 1-65535 -T 500 --timeout 0.5
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Target IP or hostname | Required |
| `-p` | Ports to scan | `1-1024` |
| `-T` | Number of threads | `100` |
| `--timeout` | Connection timeout (seconds) | `1.0` |

## Example Output

```
=================================================================
  PORT SCANNER — Daiyaan Dharsey | Cybersec Portfolio
=================================================================
  Target     : scanme.nmap.org (45.33.32.156)
  Ports      : 1024 ports
  Started    : 2026-02-24 16:30:00
=================================================================

  PORT       STATE      SERVICE            BANNER
  --------   -------   ----------------   -------------------------
  22         OPEN       SSH                SSH-2.0-OpenSSH_6.6.1p1
  80         OPEN       HTTP               HTTP/1.1 200 OK
  443        OPEN       HTTPS

=================================================================
  Scan complete: 3 open port(s) found in 12.34s
=================================================================
```

## Legal Disclaimer

This tool is intended for **authorised security testing and educational purposes only**. Only scan systems you own or have explicit written permission to test. Unauthorised port scanning may violate laws in your jurisdiction.

## Skills Demonstrated

- Python socket programming
- Multi-threading with `concurrent.futures`
- CLI argument parsing with `argparse`
- Network reconnaissance techniques
- TCP/IP fundamentals
