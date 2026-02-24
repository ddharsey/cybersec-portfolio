# IOC Enrichment Tool

A command-line threat intelligence enrichment tool that queries multiple APIs to assess Indicators of Compromise (IOCs). Supports IP addresses, file hashes, and domains.

## Features

- **Auto-detection** — automatically identifies IOC type (IP, MD5, SHA1, SHA256, domain)
- **Multi-source** — queries VirusTotal and AbuseIPDB for comprehensive coverage
- **Verdict engine** — calculates MALICIOUS / SUSPICIOUS / CLEAN verdict with confidence rating
- **Batch mode** — process a file of IOCs in one run
- **JSON output** — machine-readable output for piping into other tools or SIEM
- **Colour-coded** — terminal output with red/yellow/green verdict highlighting

## Supported IOC Types

| Type | Sources Queried | Example |
|------|----------------|---------|
| IP Address | VirusTotal + AbuseIPDB | `8.8.8.8` |
| MD5 Hash | VirusTotal | `44d88612fea8a8f36de82e1278abb02f` |
| SHA1 Hash | VirusTotal | `3395856ce81f2b7382dee72602f798b642f14140` |
| SHA256 Hash | VirusTotal | `275a021bbfb6489e54d471...` |
| Domain | VirusTotal | `example.com` |

## Setup

### 1. Install dependencies

```bash
pip install requests
```

### 2. Get free API keys

- **VirusTotal:** Sign up at [virustotal.com](https://www.virustotal.com/gui/join-us) → API key in profile
- **AbuseIPDB:** Sign up at [abuseipdb.com](https://www.abuseipdb.com/register) → API key in dashboard

### 3. Create `.env` file

Copy the example and add your keys:

```bash
cp .env.example .env
```

Edit `.env`:

```
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

## Usage

```bash
# Enrich an IP address
python ioc_enrichment.py -i 8.8.8.8

# Enrich a file hash
python ioc_enrichment.py -i 44d88612fea8a8f36de82e1278abb02f

# Enrich a domain
python ioc_enrichment.py -i evil-domain.com

# Process a batch file of IOCs
python ioc_enrichment.py -f iocs.txt

# JSON output for automation
python ioc_enrichment.py -i 1.2.3.4 --json

# Manually specify IOC type
python ioc_enrichment.py -i 8.8.8.8 --type ip
```

## Example Output

```
=================================================================
  IOC ENRICHMENT — Daiyaan Dharsey | Cybersec Portfolio
=================================================================
  Indicator  : 185.220.101.34
  Type       : ip
  Timestamp  : 2026-02-24 16:45:00
=================================================================

  [VirusTotal]
  ----------------------------------------
    Malicious              : 14
    Suspicious             : 0
    Harmless               : 56
    Undetected             : 6
    Total Engines          : 76
    Country                : DE
    As Owner               : Tor Exit Node
    Network                : 185.220.101.0/24
    Reputation             : -32

  [AbuseIPDB]
  ----------------------------------------
    Abuse Score            : 100
    Total Reports          : 2847
    Distinct Reporters     : 312
    Country                : DE
    Isp                    : Tor Network
    Usage Type             : Hosting
    Last Reported          : 2026-02-24T14:30:00+00:00

=================================================================
  VERDICT: MALICIOUS  (Confidence: HIGH)
  Reason:  14/76 engines flagged, 100% abuse confidence
=================================================================
```

## Verdict Logic

| Verdict | Conditions |
|---------|-----------|
| MALICIOUS | >30% engines flag OR abuse score ≥80 OR 10+ engines flag |
| SUSPICIOUS | >5% engines flag OR abuse score ≥25 OR 3+ engines flag |
| CLEAN | Below suspicious thresholds |

## Skills Demonstrated

- API integration (REST, authentication, error handling)
- Threat intelligence platforms (VirusTotal, AbuseIPDB)
- IOC analysis and classification
- Verdict scoring and decision logic
- Secure credential management (.env, not hardcoded)
- Batch processing and JSON output
- CLI design with argparse
