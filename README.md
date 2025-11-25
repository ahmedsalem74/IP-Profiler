```
    ██╗██████╗     ██████╗ ██████╗  ██████╗ ███████╗██╗██╗     ███████╗██████╗ 
    ██║██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██║██║     ██╔════╝██╔══██╗
    ██║██████╔╝    ██████╔╝██████╔╝██║   ██║█████╗  ██║██║     █████╗  ██████╔╝
    ██║██╔═══╝     ██╔═══╝ ██╔══██╗██║   ██║██╔══╝  ██║██║     ██╔══╝  ██╔══██╗
    ██║██║         ██║     ██║  ██║╚██████╔╝██║     ██║███████╗███████╗██║  ██║
    ╚═╝╚═╝         ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

# IP Profiler

Advanced OSINT & Threat Intelligence Engine for IP Analysis

IP Profiler is a Python-based OSINT and threat-intelligence engine that performs deep investigation on any public IP address. It combines multiple data sources — local, external, passive, and active — to provide one consolidated intelligence report suitable for SOC teams, Threat Intelligence teams, DFIR, and OSINT analysts.

---

Key Features

1. IP Classification & Context

* IP version, type, private/public, reserved, loopback
* Bogon detection
* Geolocation (via ASN DB)
* Reverse DNS lookup

2. Threat Intelligence Feeds
* VirusTotal IP reputation
* AbuseIPDB confidence score, categories, last reports
* RDAP (ARIN, RIPE, APNIC, LACNIC, AFRINIC)

  * Organization

  * Contact emails/phones

  * Event timeline

  * Network ranges

  * Abuse/NOC/Tech roles

3. OSINT Search (Google CSE)
* Multiple search variations
* Defanged IP searches
* Collect mentions from the open web
* Duplicate removal + relevancy filtering

4. ASN & Network Metadata
* ASN number
* ASN owner
* Network range
* Routing information

5. Output Options
* Console output
* JSON structured results
* Save to `results/` folder
* Integration-ready output for automation pipelines
* HTML Output ( Not the best but it's fine as a start )

---

Requirements

**Python Version**
Python **3.9+** recommended

**Install Dependencies**
Install Dependencies:

```
pip install requests geoip2 python-dateutil
```
---

  Configuration
Your script requires the following:

 **1. VirusTotal API Key**
Steps:
1. Visit https://virustotal.com
2. Create an account
3. Go to *User → API Key*
4. Copy your key

Store it:
```

export VT_API_KEY="YOUR_KEY"

```

 **2. AbuseIPDB API Key**
Steps:
1. Visit https://abuseipdb.com
2. Register
3. Retrieve your API key

Save it:
```

export ABUSEIPDB_API_KEY="YOUR_KEY"

```

 **3. Google Custom Search Engine (CSE)**
 Provided credentials:
- **API Key:** `A******************************************o`
- **Search Engine ID:** `9*********************3`

Documentation steps:
1. Visit https://cse.google.com
2. Create a CSE
3. Choose "Search the entire web"
4. Enable Custom Search API in Google Cloud
5. Retrieve your key and CSE ID

Add as environment variables:
```

export GOOGLE_API_KEY="YOUR_KEY"
export GOOGLE_CSE_ID="YOUR_CX"

```

 **4. MaxMind GeoLite2 ASN Database**
1. Create a free MaxMind account
2. Download GeoLite2 ASN
3. Extract `GeoLite2-ASN.mmdb`
4. Place in your project:
```

IP-Profiler/
data/
GeoLite2-ASN.mmdb

```
Update your script:
```

ASN_DB_PATH = r"data/GeoLite2-ASN.mmdb"

```

---

  Usage
Run directly:
```

python ip_profiler.py 8.8.8.8

````

Or import:
```python
from ip_profiler import run_ip_profiler
result = run_ip_profiler("1.1.1.1")
````

---

Output Example (Excerpt)
**Summary**

```
IP: 8.8.8.8
Type: Public / Global
ASN: AS15169 (Google LLC)
Geolocation: US
Bogon: No
Reverse DNS: dns.google
```

**VirusTotal**

```
Reputation: 0 (clean)
Detections: 0/93 engines
Tags: cdn, public-dns, resolver
```

**AbuseIPDB**

```
Abuse Score: 4 (Low)
Recent Reports: 2
Last Reported: 2025-02-05
Categories: Web Attack, SSH Bruteforce
```

**RDAP**

```
Organization: Google LLC
Country: US
CIDR: 8.8.8.0/24
Contacts: Abuse, NOC, Admin, Tech
Created: 1992-12-01
```

**Google OSINT**

```
Found 14 mentions:
- "8.8.8.8 in phishing campaign"
- "8.8.8.8 flagged on abuse thread"
...
```

---

Security Notes

* Never commit API keys
* Use `.env` or OS variables
* Add `.env`, `*.mmdb`, `results/`, and your keys to `.gitignore`
* Rotate VT/Google API keys periodically

---

#Future Roadmap
IP Profiler will expand into a full threat-intelligence engine.

**Planned Features**

SSL/TLS Correlation

* Fetch SSL certificate from IP (if HTTPS)
* Parse:

  * Issuer
  * SAN names
  * Expiration
  * Fingerprints (SHA1/SHA256)
* Domain ↔ certificate correlation
* Passive DNS alignment

  Open Ports & Services
* Automated port scanning
* Detect common services:

  * HTTP/HTTPS
  * SSH
  * RDP
  * FTP
  * SMTP/IMAP
  * Custom ports
* Banner grabbing
* Fingerprint recognition

  Additional OSINT Sources
* Shodan integration
* Censys lookup
* AlienVault OTX
* GreyNoise behavior analysis

  Visualization Enhancements
* Graph-based relationships:

  * ASN → IP → OSINT mentions
  * SSL certificate → domains → WHOIS
* HTML reporting
* PDF export

  Threat Intelligence Automation
* Threat scoring system
* Pattern detection
* Historical IP tracking
* IOC enrichment pipeline
