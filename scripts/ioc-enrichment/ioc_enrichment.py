"""
IOC Enrichment Tool — Cybersecurity Portfolio
Author: Daiyaan Dharsey
Description: Queries threat intelligence APIs to enrich Indicators of Compromise (IOCs).
             Supports IP addresses, file hashes (MD5/SHA1/SHA256), and domains.
             Integrates with VirusTotal and AbuseIPDB free-tier APIs.

Usage:
    python ioc_enrichment.py -i <indicator>
    python ioc_enrichment.py -i <indicator> --type ip
    python ioc_enrichment.py -f <file_with_iocs>
    python ioc_enrichment.py -i 8.8.8.8 --json

Setup:
    1. Get free API keys:
       - VirusTotal:  https://www.virustotal.com/gui/join-us
       - AbuseIPDB:   https://www.abuseipdb.com/register

    2. Create a .env file in the same directory:
       VT_API_KEY=your_virustotal_api_key_here
       ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime

import requests


# =============================================================================
#  Configuration
# =============================================================================

def load_api_keys() -> dict:
    """Load API keys from .env file or environment variables."""
    keys = {
        "VT_API_KEY": os.environ.get("VT_API_KEY", ""),
        "ABUSEIPDB_API_KEY": os.environ.get("ABUSEIPDB_API_KEY", ""),
    }

    # Try loading from .env file
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    keys[key.strip()] = value.strip()

    return keys


API_KEYS = load_api_keys()


# =============================================================================
#  IOC Type Detection
# =============================================================================

def detect_ioc_type(indicator: str) -> str:
    """
    Automatically detect the IOC type based on pattern matching.
    Returns: 'ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', or 'unknown'
    """
    indicator = indicator.strip()

    # Check if it's an IP address
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass

    # Check for file hashes
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "hash_sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "hash_sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "hash_md5"

    # Check for domain pattern
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", indicator):
        return "domain"

    return "unknown"


# =============================================================================
#  VirusTotal Lookups
# =============================================================================

def vt_lookup_ip(ip: str) -> dict:
    """Query VirusTotal for IP address reputation."""
    if not API_KEYS.get("VT_API_KEY"):
        return {"error": "VT_API_KEY not configured"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEYS["VT_API_KEY"]}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "indicator": ip,
                "type": "IP Address",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "country": data.get("country", "N/A"),
                "as_owner": data.get("as_owner", "N/A"),
                "network": data.get("network", "N/A"),
                "reputation": data.get("reputation", "N/A"),
            }
        elif response.status_code == 401:
            return {"error": "Invalid VT_API_KEY"}
        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded (4 req/min on free tier)"}
        else:
            return {"error": f"VT returned status {response.status_code}"}
    except requests.RequestException as e:
        return {"error": f"VT request failed: {str(e)}"}


def vt_lookup_hash(file_hash: str) -> dict:
    """Query VirusTotal for file hash reputation."""
    if not API_KEYS.get("VT_API_KEY"):
        return {"error": "VT_API_KEY not configured"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEYS["VT_API_KEY"]}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "indicator": file_hash,
                "type": "File Hash",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "file_name": data.get("meaningful_name", "N/A"),
                "file_type": data.get("type_description", "N/A"),
                "file_size": data.get("size", "N/A"),
                "sha256": data.get("sha256", "N/A"),
                "first_seen": data.get("first_submission_date", "N/A"),
                "tags": ", ".join(data.get("tags", [])) or "None",
            }
        elif response.status_code == 404:
            return {"source": "VirusTotal", "indicator": file_hash, "result": "Not found in VT database"}
        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded (4 req/min on free tier)"}
        else:
            return {"error": f"VT returned status {response.status_code}"}
    except requests.RequestException as e:
        return {"error": f"VT request failed: {str(e)}"}


def vt_lookup_domain(domain: str) -> dict:
    """Query VirusTotal for domain reputation."""
    if not API_KEYS.get("VT_API_KEY"):
        return {"error": "VT_API_KEY not configured"}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": API_KEYS["VT_API_KEY"]}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "indicator": domain,
                "type": "Domain",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "registrar": data.get("registrar", "N/A"),
                "creation_date": data.get("creation_date", "N/A"),
                "reputation": data.get("reputation", "N/A"),
                "categories": str(data.get("categories", {})) or "N/A",
            }
        elif response.status_code == 404:
            return {"source": "VirusTotal", "indicator": domain, "result": "Not found in VT database"}
        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded (4 req/min on free tier)"}
        else:
            return {"error": f"VT returned status {response.status_code}"}
    except requests.RequestException as e:
        return {"error": f"VT request failed: {str(e)}"}


# =============================================================================
#  AbuseIPDB Lookup
# =============================================================================

def abuseipdb_lookup(ip: str) -> dict:
    """Query AbuseIPDB for IP abuse reports."""
    if not API_KEYS.get("ABUSEIPDB_API_KEY"):
        return {"error": "ABUSEIPDB_API_KEY not configured"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEYS["ABUSEIPDB_API_KEY"],
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "source": "AbuseIPDB",
                "indicator": ip,
                "type": "IP Address",
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "distinct_reporters": data.get("numDistinctUsers", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "domain": data.get("domain", "N/A"),
                "usage_type": data.get("usageType", "N/A"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "last_reported": data.get("lastReportedAt", "Never"),
            }
        elif response.status_code == 401:
            return {"error": "Invalid ABUSEIPDB_API_KEY"}
        elif response.status_code == 429:
            return {"error": "AbuseIPDB rate limit exceeded"}
        else:
            return {"error": f"AbuseIPDB returned status {response.status_code}"}
    except requests.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {str(e)}"}


# =============================================================================
#  Verdict Engine
# =============================================================================

def calculate_verdict(results: list[dict]) -> dict:
    """
    Analyse enrichment results and return an overall verdict.
    Returns a dict with verdict, confidence, and reasoning.
    """
    total_malicious = 0
    total_engines = 0
    abuse_score = 0
    has_data = False

    for result in results:
        if "error" in result:
            continue
        has_data = True

        if "malicious" in result:
            total_malicious += result["malicious"]
            total_engines += result.get("total_engines", 0)

        if "abuse_score" in result:
            abuse_score = result["abuse_score"]

    if not has_data:
        return {
            "verdict": "UNKNOWN",
            "confidence": "N/A",
            "reasoning": "No data returned from any source",
        }

    # Scoring logic
    mal_ratio = total_malicious / total_engines if total_engines > 0 else 0

    if mal_ratio > 0.3 or abuse_score >= 80 or total_malicious >= 10:
        verdict = "MALICIOUS"
        confidence = "HIGH" if (mal_ratio > 0.5 or abuse_score >= 90) else "MEDIUM"
        reasoning = f"{total_malicious}/{total_engines} engines flagged"
        if abuse_score > 0:
            reasoning += f", {abuse_score}% abuse confidence"
    elif mal_ratio > 0.05 or abuse_score >= 25 or total_malicious >= 3:
        verdict = "SUSPICIOUS"
        confidence = "MEDIUM"
        reasoning = f"{total_malicious}/{total_engines} engines flagged"
        if abuse_score > 0:
            reasoning += f", {abuse_score}% abuse confidence"
    else:
        verdict = "CLEAN"
        confidence = "HIGH" if total_engines > 50 else "MEDIUM"
        reasoning = f"{total_malicious}/{total_engines} engines flagged"
        if abuse_score > 0:
            reasoning += f", {abuse_score}% abuse confidence"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
    }


# =============================================================================
#  Output Formatting
# =============================================================================

VERDICT_COLOURS = {
    "MALICIOUS": "\033[91m",   # Red
    "SUSPICIOUS": "\033[93m",  # Yellow
    "CLEAN": "\033[92m",       # Green
    "UNKNOWN": "\033[90m",     # Grey
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_header(indicator: str, ioc_type: str):
    """Print scan header."""
    print(f"\n{'=' * 65}")
    print(f"  IOC ENRICHMENT — Daiyaan Dharsey | Cybersec Portfolio")
    print(f"{'=' * 65}")
    print(f"  Indicator  : {indicator}")
    print(f"  Type       : {ioc_type}")
    print(f"  Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 65}")


def print_source_results(result: dict):
    """Print results from a single source."""
    if "error" in result:
        print(f"\n  [{result.get('source', 'Unknown')}] Error: {result['error']}")
        return

    source = result.get("source", "Unknown")
    print(f"\n  [{source}]")
    print(f"  {'-' * 40}")

    skip_keys = {"source", "indicator", "type"}
    for key, value in result.items():
        if key in skip_keys:
            continue
        label = key.replace("_", " ").title()
        print(f"    {label:<22} : {value}")


def print_verdict(verdict: dict):
    """Print the final verdict with colour coding."""
    v = verdict["verdict"]
    colour = VERDICT_COLOURS.get(v, RESET)

    print(f"\n{'=' * 65}")
    print(f"  VERDICT: {colour}{BOLD}{v}{RESET}  (Confidence: {verdict['confidence']})")
    print(f"  Reason:  {verdict['reasoning']}")
    print(f"{'=' * 65}\n")


def output_json(indicator: str, ioc_type: str, results: list[dict], verdict: dict):
    """Output results as JSON for piping or logging."""
    output = {
        "indicator": indicator,
        "type": ioc_type,
        "timestamp": datetime.now().isoformat(),
        "sources": results,
        "verdict": verdict,
    }
    print(json.dumps(output, indent=2, default=str))


# =============================================================================
#  Enrichment Orchestrator
# =============================================================================

def enrich_ioc(indicator: str, ioc_type: str) -> tuple[list[dict], dict]:
    """
    Run all relevant lookups for an IOC and return results + verdict.
    """
    results = []

    if ioc_type == "ip":
        results.append(vt_lookup_ip(indicator))
        results.append(abuseipdb_lookup(indicator))

    elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        results.append(vt_lookup_hash(indicator))

    elif ioc_type == "domain":
        results.append(vt_lookup_domain(indicator))

    else:
        results.append({"error": f"Unsupported IOC type: {ioc_type}"})

    verdict = calculate_verdict(results)
    return results, verdict


def process_file(filepath: str, output_json_flag: bool):
    """Process a file containing one IOC per line."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "r") as f:
        indicators = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"\n[*] Processing {len(indicators)} IOCs from {filepath}\n")

    all_results = []
    for indicator in indicators:
        ioc_type = detect_ioc_type(indicator)
        if ioc_type == "unknown":
            print(f"  [!] Skipping unrecognised indicator: {indicator}")
            continue

        results, verdict = enrich_ioc(indicator, ioc_type)

        if output_json_flag:
            all_results.append({
                "indicator": indicator,
                "type": ioc_type,
                "sources": results,
                "verdict": verdict,
            })
        else:
            print_header(indicator, ioc_type)
            for result in results:
                print_source_results(result)
            print_verdict(verdict)

    if output_json_flag:
        print(json.dumps(all_results, indent=2, default=str))


# =============================================================================
#  CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="IOC Enrichment Tool — Query threat intel APIs for IOC reputation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ioc_enrichment.py -i 8.8.8.8
  python ioc_enrichment.py -i 44d88612fea8a8f36de82e1278abb02f
  python ioc_enrichment.py -i evil-domain.com
  python ioc_enrichment.py -f iocs.txt
  python ioc_enrichment.py -i 1.2.3.4 --json
        """,
    )
    parser.add_argument(
        "-i", "--indicator", help="Single IOC to enrich (IP, hash, or domain)"
    )
    parser.add_argument(
        "-f", "--file", help="File containing IOCs (one per line)"
    )
    parser.add_argument(
        "--type",
        choices=["ip", "domain", "hash_md5", "hash_sha1", "hash_sha256"],
        help="Manually specify IOC type (auto-detected if not set)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )

    args = parser.parse_args()

    if not args.indicator and not args.file:
        parser.print_help()
        sys.exit(1)

    # Batch file mode
    if args.file:
        process_file(args.file, args.json)
        return

    # Single indicator mode
    indicator = args.indicator.strip()
    ioc_type = args.type if args.type else detect_ioc_type(indicator)

    if ioc_type == "unknown":
        print(f"[!] Could not detect IOC type for: {indicator}")
        print("[*] Use --type to specify manually")
        sys.exit(1)

    results, verdict = enrich_ioc(indicator, ioc_type)

    if args.json:
        output_json(indicator, ioc_type, results, verdict)
    else:
        print_header(indicator, ioc_type)
        for result in results:
            print_source_results(result)
        print_verdict(verdict)


if __name__ == "__main__":
    main()
