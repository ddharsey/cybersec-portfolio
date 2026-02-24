"""
Port Scanner — Cybersecurity Portfolio Tool
Author: Daiyaan Dharsey
Description: A multi-threaded TCP port scanner with service identification,
             banner grabbing, and clean reporting output.
Usage:
    python port_scanner.py -t <target> [-p <ports>] [-T <threads>] [--timeout <seconds>]

Examples:
    python port_scanner.py -t 192.168.1.1
    python port_scanner.py -t scanme.nmap.org -p 1-1000
    python port_scanner.py -t 10.0.0.1 -p 22,80,443,3389
    python port_scanner.py -t 192.168.1.1 -p 1-65535 -T 200
"""

import socket
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports and their associated services
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1434: "MSSQL-UDP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{target}'")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Attempt to grab the service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        sock.close()
        # Return first line only for clean output
        return banner.split("\n")[0][:80] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float) -> dict | None:
    """
    Scan a single TCP port.
    Returns a dict with port info if open, None if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            banner = grab_banner(ip, port, timeout)
            return {
                "port": port,
                "state": "OPEN",
                "service": service,
                "banner": banner,
            }
        return None

    except socket.error:
        return None


def parse_ports(port_arg: str) -> list[int]:
    """
    Parse port argument into a list of ports.
    Supports: '80' | '22,80,443' | '1-1000' | '22,80,443,8000-9000'
    """
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                print(f"[!] Invalid port range: {part}")
                sys.exit(1)
            ports.extend(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                print(f"[!] Invalid port: {port}")
                sys.exit(1)
            ports.append(port)
    return sorted(set(ports))


def print_header(target: str, ip: str, ports: list[int]):
    """Print scan header information."""
    print("\n" + "=" * 65)
    print(f"  PORT SCANNER — Daiyaan Dharsey | Cybersec Portfolio")
    print("=" * 65)
    print(f"  Target     : {target} ({ip})")
    print(f"  Ports      : {len(ports)} ports")
    print(f"  Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)
    print(f"\n  {'PORT':<10} {'STATE':<10} {'SERVICE':<18} {'BANNER'}")
    print(f"  {'-'*8}   {'-'*7}   {'-'*16}   {'-'*25}")


def print_results(results: list[dict], start_time: datetime):
    """Print scan summary."""
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n{'=' * 65}")
    print(f"  Scan complete: {len(results)} open port(s) found in {elapsed:.2f}s")
    print(f"{'=' * 65}\n")


def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner — Cybersecurity Portfolio Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t scanme.nmap.org
  python port_scanner.py -t 192.168.1.1 -p 1-1000
  python port_scanner.py -t 10.0.0.1 -p 22,80,443,3389 -T 50
        """,
    )
    parser.add_argument(
        "-t", "--target", required=True, help="Target IP address or hostname"
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Ports to scan (default: 1-1024). Examples: '80' | '22,80,443' | '1-1000'",
    )
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=100,
        help="Number of threads (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )

    args = parser.parse_args()

    # Resolve and validate target
    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)

    # Display header
    print_header(args.target, ip, ports)

    # Run the scan
    open_ports = []
    start_time = datetime.now()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(scan_port, ip, port, args.timeout): port
                for port in ports
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    banner_text = f"  {result['banner']}" if result["banner"] else ""
                    print(
                        f"  {result['port']:<10} {result['state']:<10} "
                        f"{result['service']:<18}{banner_text}"
                    )

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)

    # Sort and print summary
    open_ports.sort(key=lambda x: x["port"])
    print_results(open_ports, start_time)


if __name__ == "__main__":
    main()
