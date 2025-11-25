import ipaddress
import socket
import requests
import geoip2.database
import json
from datetime import datetime
import subprocess
import os
import sys
import time

# =============================================================================
# CONFIGURATION
# =============================================================================

# MaxMind ASN Database
ASN_DB_PATH = r"N:/Mini project/IP lookUp project/GeoLite2-ASN_20251122/GeoLite2-ASN.mmdb"

# VirusTotal API
VT_API_KEY = "fd15e149566b26605d5807514e010a5860d9e8ae60f04fedb1e3db074cfbc718"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# AbuseIPDB API
ABUSEIPDB_API_KEY = "ced729784cafa2bf95c8d3c0316f7ce23b0badd2b373d9e56fa3232bb715cbe5adeb9505a88b056f"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Google Custom Search API
GOOGLE_API_KEY = "AIzaSyBqExeS_6JDeqxich3MPnfnF4CNkyT64oo"
GOOGLE_CSE_ID = "93cbe98d182804bc3"
GOOGLE_NUM_RESULTS = 10
GOOGLE_MAX_TOTAL_RESULTS = 50
GOOGLE_DELAY_BETWEEN_REQUESTS = 1

# BOGON Ranges
BOGON_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", 
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4"
]
BOGON_NETWORKS = [ipaddress.ip_network(net) for net in BOGON_RANGES]

# RDAP Servers
RDAP_SERVERS = {
    "arin": "https://rdap.arin.net/registry/ip/",
    "ripe": "https://rdap.db.ripe.net/ip/",
    "apnic": "https://rdap.apnic.net/ip/",
    "lacnic": "https://rdap.lacnic.net/rdap/ip/",
    "afrinic": "https://rdap.afrinic.net/rdap/ip/"
}

# Abuse Categories Mapping
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}

# =============================================================================
# CORE IP FUNCTIONS
# =============================================================================

def validate_ip(ip_str: str):
    """Validate IP address format"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return True, ip_obj
    except ValueError:
        return False, None

def check_bogon(ip_obj):
    """Check if IP is in bogon ranges"""
    if ip_obj.version == 4:
        for net in BOGON_NETWORKS:
            if ip_obj in net:
                return True
    return False

def classify_ip(ip_obj):
    """Comprehensive IP classification"""
    return {
        "IP Version": "IPv4" if ip_obj.version == 4 else "IPv6",
        "Private": ip_obj.is_private,
        "Multicast": ip_obj.is_multicast,
        "Reserved": ip_obj.is_reserved,
        "Loopback": ip_obj.is_loopback,
        "Link Local": ip_obj.is_link_local,
        "Global": ip_obj.is_global,
        "Bogon": check_bogon(ip_obj),
    }

def reverse_dns_lookup(ip):
    """Perform reverse DNS lookup"""
    try:
        host = socket.gethostbyaddr(ip)
        return {
            "Hostname": host[0],
            "Aliases": host[1],
            "IP Addresses": host[2]
        }
    except socket.herror:
        return {"Hostname": "Not found", "Error": "No PTR record"}
    except Exception as e:
        return {"Hostname": "Error", "Error": str(e)}

# =============================================================================
# ASN LOOKUP (MAXMIND)
# =============================================================================

def lookup_asn(ip_str):
    """ASN lookup using MaxMind database"""
    try:
        reader = geoip2.database.Reader(ASN_DB_PATH)
        response = reader.asn(ip_str)
        reader.close()
        
        return {
            "AS Number": f"AS{response.autonomous_system_number}",
            "Organization": response.autonomous_system_organization,
            "Network Range": str(response.network),
        }
    except Exception as e:
        return {"Error": f"ASN Lookup failed: {e}"}

# =============================================================================
# RDAP LOOKUP
# =============================================================================

def parse_vcard(vcard_array):
    """Parse vCard data to extract contact information"""
    if not vcard_array or len(vcard_array) < 2:
        return {}
    
    contact = {}
    for item in vcard_array[1]:
        if item[0] == "fn":
            contact["name"] = item[3]
        elif item[0] == "email":
            contact["email"] = item[3]
        elif item[0] == "tel":
            contact["phone"] = item[3].get("text", item[3]) if isinstance(item[3], dict) else item[3]
        elif item[0] == "adr":
            if "label" in item[1]:
                contact["address"] = item[1]["label"]
    return contact

def parse_entities(entities):
    """Parse entity information and extract contacts by role"""
    contacts = {
        "administrative": [],
        "technical": [],
        "abuse": [],
        "noc": [],
        "other": []
    }
    
    for entity in entities:
        roles = entity.get("roles", [])
        handle = entity.get("handle", "")
        vcard = parse_vcard(entity.get("vcardArray", []))
        
        if vcard:
            contact_info = {
                "handle": handle,
                "name": vcard.get("name", ""),
                "email": vcard.get("email", ""),
                "phone": vcard.get("phone", ""),
                "address": vcard.get("address", "")
            }
            
            # Assign to appropriate role category
            assigned = False
            for role in roles:
                if role in contacts:
                    contacts[role].append(contact_info)
                    assigned = True
                    break
            
            if not assigned:
                contacts["other"].append(contact_info)
    
    return contacts

def parse_events(events):
    """Parse event timeline"""
    timeline = {}
    for event in events:
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action and date:
            try:
                dt = datetime.fromisoformat(date.replace('Z', '+00:00'))
                readable_date = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except:
                readable_date = date
            timeline[action] = readable_date
    return timeline

def rdap_lookup(ip):
    """Perform RDAP lookup across all RIRs"""
    for rir, base in RDAP_SERVERS.items():
        try:
            resp = requests.get(base + ip, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                
                return {
                    "RIR": rir.upper(),
                    "Network Handle": data.get("handle", ""),
                    "Network Name": data.get("name", ""),
                    "IP Range": f"{data.get('startAddress', '')} - {data.get('endAddress', '')}",
                    "CIDR": data.get("cidr0_cidrs", [{}])[0].get("cidr", "") if data.get("cidr0_cidrs") else "",
                    "Type": data.get("type", ""),
                    "Country": data.get("country", ""),
                    "Parent Handle": data.get("parentHandle", ""),
                    "Status": ", ".join(data.get("status", [])),
                    "Contacts": parse_entities(data.get("entities", [])),
                    "Timeline": parse_events(data.get("events", [])),
                    "Raw Entities Count": len(data.get("entities", [])),
                }
        except Exception:
            continue
    return {"Error": "No RDAP information found from any RIR"}

# =============================================================================
# ABUSEIPDB INTEGRATION
# =============================================================================

def abuseipdb_lookup(ip, max_age_days=90):
    """Perform AbuseIPDB lookup for IP reputation"""
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': max_age_days,
        'verbose': True  # Get detailed reports
    }
    
    try:
        response = requests.request(
            method='GET', 
            url=ABUSEIPDB_URL, 
            headers=headers, 
            params=querystring,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return parse_abuseipdb_data(data)
        else:
            return {"Error": f"AbuseIPDB API Error: {response.status_code}"}
            
    except Exception as e:
        return {"Error": f"AbuseIPDB lookup failed: {e}"}

def parse_abuseipdb_data(data):
    """Parse and format AbuseIPDB response data"""
    if not data:
        return {"Error": "No data received from AbuseIPDB"}
    
    # Parse abuse categories from reports
    reports = data.get('reports', [])
    category_counts = {}
    recent_reports = []
    
    for report in reports[:5]:  # Process first 5 reports for summary
        categories = report.get('categories', [])
        for category_id in categories:
            category_name = ABUSE_CATEGORIES.get(category_id, f"Unknown ({category_id})")
            category_counts[category_name] = category_counts.get(category_name, 0) + 1
        
        # Format recent report
        recent_reports.append({
            "date": report.get('reportedAt', ''),
            "comment": report.get('comment', ''),
            "categories": [ABUSE_CATEGORIES.get(cat, cat) for cat in categories],
            "reporter_country": report.get('reporterCountryName', '')
        })
    
    # Determine threat level based on confidence score
    confidence_score = data.get('abuseConfidenceScore', 0)
    if confidence_score >= 80:
        threat_level = "HIGH"
    elif confidence_score >= 50:
        threat_level = "MEDIUM"
    elif confidence_score >= 25:
        threat_level = "LOW"
    else:
        threat_level = "CLEAN"
    
    return {
        "abuse_confidence_score": confidence_score,
        "threat_level": threat_level,
        "is_public": data.get('isPublic', False),
        "is_whitelisted": data.get('isWhitelisted', False),
        "total_reports": data.get('totalReports', 0),
        "distinct_users": data.get('numDistinctUsers', 0),
        "last_reported": data.get('lastReportedAt', ''),
        "country_code": data.get('countryCode', ''),
        "country_name": data.get('countryName', ''),
        "usage_type": data.get('usageType', ''),
        "isp": data.get('isp', ''),
        "domain": data.get('domain', ''),
        "hostnames": data.get('hostnames', []),
        "is_tor": data.get('isTor', False),
        "category_breakdown": category_counts,
        "recent_reports": recent_reports
    }

# =============================================================================
# VIRUSTOTAL INTEGRATION
# =============================================================================

def vt_ip_lookup(ip):
    """Comprehensive VirusTotal IP analysis"""
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(VT_URL.format(ip), headers=headers, timeout=15)
        if response.status_code != 200:
            return {"error": f"API Error {response.status_code}"}

        data = response.json()
        attr = data.get("data", {}).get("attributes", {})

        # Enhanced data extraction
        return {
            "reputation": attr.get("reputation", 0),
            "last_analysis_stats": attr.get("last_analysis_stats", {}),
            "last_analysis_results": attr.get("last_analysis_results", {}),
            "as_owner": attr.get("as_owner", ""),
            "asn": attr.get("asn", ""),
            "country": attr.get("country", ""),
            "jarm": attr.get("jarm", ""),
            "tags": attr.get("tags", []),
            "whois": attr.get("whois", ""),
            "whois_date": attr.get("whois_date", ""),
            "last_modification_date": attr.get("last_modification_date", ""),
            "passive_dns": attr.get("resolutions", []),
            "related_domains": attr.get("last_https_certificate", {}).get("extensions", {}).get("subject_alt_name", []),
            "dns_records": attr.get("dns_records", []),
            "regional_internet_registry": attr.get("regional_internet_registry", ""),
            "network": attr.get("network", "")
        }

    except Exception as e:
        return {"error": f"VirusTotal lookup failed: {e}"}

# =============================================================================
# ONLINE SEARCH INTEGRATION (DIRECT IMPLEMENTATION)
# =============================================================================

def simple_ip_variations(ip):
    """Generate IP variations for search"""
    parts = ip.split(".")
    variations = [
        ip,
        "[.]".join(parts),
        f"{parts[0]}.{parts[1]}.{parts[2]}[.]{parts[3]}",
        f"{parts[0]}[.]{parts[1]}.{parts[2]}.{parts[3]}",
        ".".join(parts).replace(".", "(.)"),
        f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
    ]
    return list(dict.fromkeys(variations))  # Remove duplicates

def google_search(query, api_key=GOOGLE_API_KEY, cse_id=GOOGLE_CSE_ID, num_results=GOOGLE_NUM_RESULTS, start_index=1):
    """Perform Google Custom Search"""
    url = "https://www.googleapis.com/customsearch/v1"
    params = {"key": api_key, "cx": cse_id, "q": query, "num": num_results, "start": start_index}
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        links = []
        for item in data.get("items", []):
            links.append({
                "title": item.get("title", "No Title"),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "query": query,
                "searchDate": datetime.now().isoformat()
            })
        return links
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Google API query failed: {e}")
        return []

def search_ip_mentions(ip):
    """Search for IP mentions online using Google Custom Search"""
    variations = simple_ip_variations(ip)
    all_results = []
    collected_urls = set()
    
    print(f"[INFO] Searching for {ip} in {len(variations)} variations...")

    for var in variations:
        print(f"[SEARCH] Querying for: '{var}'")
        for start_index in [1, 11]:
            if len(all_results) >= GOOGLE_MAX_TOTAL_RESULTS:
                break
            results = google_search(f'"{var}"', start_index=start_index)
            for r in results:
                if r["link"] not in collected_urls:
                    all_results.append(r)
                    collected_urls.add(r["link"])
            print(f"       Found {len(results)} results (page starting at {start_index})")
            time.sleep(GOOGLE_DELAY_BETWEEN_REQUESTS)

    print(f"[INFO] Total unique mentions found: {len(all_results)}")
    return all_results

def online_search_ip(ip):
    """Perform online search analysis - integrated version"""
    try:
        print(f"Starting online search for IP: {ip}")
        results = search_ip_mentions(ip)
        
        if results:
            # Format results for display
            formatted_output = []
            formatted_output.append(f"ONLINE SEARCH RESULTS FOR: {ip}")
            formatted_output.append("=" * 60)
            formatted_output.append(f"Total unique mentions found: {len(results)}")
            formatted_output.append(f"Search variations used: {len(simple_ip_variations(ip))}")
            formatted_output.append(f"Unique domains found: {len(set(r['link'] for r in results))}")
            formatted_output.append("")
            
            # Group by query type
            query_groups = {}
            for result in results:
                query = result['query']
                if query not in query_groups:
                    query_groups[query] = []
                query_groups[query].append(result)
            
            for query, query_results in query_groups.items():
                formatted_output.append(f"QUERY: '{query}' ({len(query_results)} results)")
                formatted_output.append("-" * 40)
                for i, result in enumerate(query_results[:3], 1):  # Show top 3 per query
                    snippet = result['snippet']
                    if len(snippet) > 100:
                        snippet = snippet[:100] + "..."
                    formatted_output.append(f"{i}. {result['title']}")
                    formatted_output.append(f"   {result['link']}")
                    formatted_output.append(f"   {snippet}")
                    formatted_output.append("")
            
            output_text = "\n".join(formatted_output)
            
            return {
                "success": True,
                "output": output_text,
                "results_count": len(results),
                "raw_results": results,
                "error": None
            }
        else:
            return {
                "success": True,
                "output": f"No online mentions found for IP: {ip}",
                "results_count": 0,
                "raw_results": [],
                "error": None
            }
            
    except Exception as e:
        error_msg = f"Online search failed: {str(e)}"
        print(f"ERROR: {error_msg}")
        return {
            "success": False,
            "output": None,
            "results_count": 0,
            "raw_results": [],
            "error": error_msg
        }

# =============================================================================
# HTML REPORT GENERATION
# =============================================================================

def generate_online_search_html_report(ip, results, filename=None):
    """Generate a separate HTML report specifically for online search results"""
    if filename is None:
        filename = f"ip_mentions_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Mention Search Report - {ip}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6; color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }}
        .container {{ max-width: 1200px; margin:0 auto; }}
        .header {{
            background: rgba(255,255,255,0.95); backdrop-filter: blur(10px);
            padding:30px; border-radius:15px; box-shadow:0 8px 32px rgba(0,0,0,0.1);
            margin-bottom:30px; text-align:center;
        }}
        .header h1 {{ color:#2c3e50; font-size:2.5em; margin-bottom:10px; }}
        .header .ip-address {{
            color:#e74c3c; font-family:'Courier New', monospace; font-size:1.8em; font-weight:bold;
            background:#f8f9fa; padding:10px 20px; border-radius:8px; display:inline-block;
            margin:10px 0;
        }}
        .stats {{
            display:flex; justify-content:center; gap:30px; margin-top:20px; flex-wrap:wrap;
        }}
        .stat-card {{
            background: linear-gradient(45deg,#3498db,#2980b9); color:white;
            padding:20px; border-radius:10px; text-align:center; min-width:150px;
            box-shadow:0 4px 15px rgba(0,0,0,0.2);
        }}
        .stat-number {{ font-size:2em; font-weight:bold; margin-bottom:5px; }}
        .results-grid {{ display:grid; gap:20px; }}
        .result-card {{
            background: rgba(255,255,255,0.95); backdrop-filter: blur(10px);
            padding:25px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.1);
            border-left:5px solid #3498db; transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        .result-card:hover {{ transform: translateY(-5px); box-shadow:0 8px 30px rgba(0,0,0,0.15); }}
        .result-title {{ color:#2c3e50; font-size:1.3em; font-weight:600; margin-bottom:10px; }}
        .result-title a {{ color: inherit; text-decoration:none; }}
        .result-title a:hover {{ color:#3498db; }}
        .result-url {{ color:#7f8c8d; font-size:0.9em; margin-bottom:15px; word-break:break-all; }}
        .result-snippet {{ color:#555; line-height:1.5; margin-bottom:10px; }}
        .result-meta {{
            display:flex; justify-content:space-between; align-items:center; margin-top:15px;
            padding-top:15px; border-top:1px solid #ecf0f1; font-size:0.85em; color:#7f8c8d;
        }}
        .query-badge {{ background:#e74c3c; color:white; padding:4px 8px; border-radius:12px; font-size:0.8em; }}
        .no-results {{ text-align:center; padding:60px 20px; color:#7f8c8d; font-size:1.2em; }}
        .footer {{ text-align:center; margin-top:40px; color:rgba(255,255,255,0.8); font-size:0.9em; }}
        @media (max-width:768px) {{
            .header h1 {{ font-size:2em; }}
            .header .ip-address {{ font-size:1.4em; }}
            .stats {{ flex-direction:column; align-items:center; }}
            .stat-card {{ width:100%; max-width:200px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IP Mention Search Report</h1>
            <div class="ip-address">{ip}</div>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(results)}</div>
                    <div>Total Results</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(set(r['query'] for r in results))}</div>
                    <div>Search Variations</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(set(r['link'] for r in results))}</div>
                    <div>Unique Domains</div>
                </div>
            </div>
        </div>
        
        <div class="results-grid">
"""

    if results:
        for res in results:
            snippet = res.get("snippet", "No snippet available")
            if len(snippet) > 200:
                snippet = snippet[:200] + "..."
            html_template += f"""
                <div class="result-card">
                    <div class="result-title">
                        <a href="{res['link']}" target="_blank">{res['title']}</a>
                    </div>
                    <div class="result-url">{res['link']}</div>
                    <div class="result-snippet">{snippet}</div>
                    <div class="result-meta">
                        <span class="query-badge">Query: {res.get('query','N/A')}</span>
                        <span>Found: {res.get('searchDate','N/A')[:16]}</span>
                    </div>
                </div>
            """
    else:
        html_template += """
            <div class="no-results">
                <h3>No Results Found</h3>
                <p>No mentions of this IP address were found in the search results.</p>
            </div>
        """

    html_template += f"""
            </div>
            <div class="footer">
                <p>Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
                <p>Powered by Google Custom Search API</p>
            </div>
        </div>
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                const links = document.querySelectorAll('.result-title a');
                links.forEach(link => {{
                    link.addEventListener('click', function() {{
                        console.log(`Link clicked: ${{this.textContent}}`);
                    }});
                }});
                const scrollToTop = document.createElement('button');
                scrollToTop.textContent = 'Top';
                scrollToTop.style.cssText = `
                    position: fixed; bottom:20px; right:20px; background:#3498db; color:white;
                    border:none; padding:10px 15px; border-radius:50%; cursor:pointer;
                    font-size:16px; box-shadow:0 4px 15px rgba(0,0,0,0.2); z-index:1000;
                `;
                scrollToTop.addEventListener('click', () => {{
                    window.scrollTo({{ top:0, behavior:'smooth' }});
                }});
                document.body.appendChild(scrollToTop);
            }});
        </script>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f"[SUCCESS] Online search HTML report generated: {filename}")
    return filename

def get_css_styles():
    """Return the CSS styles for the HTML report"""
    return """
        :root {
            --primary: #4361ee;
            --secondary: #3a0ca3;
            --success: #4cc9f0;
            --warning: #f72585;
            --danger: #e63946;
            --light: #f8f9fa;
            --dark: #212529;
            --gray: #6c757d;
            --border-radius: 8px;
            --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background-color: #f5f7fb;
            color: var(--dark);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 30px 0;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border-radius: var(--border-radius);
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }

        h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .section {
            background: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            margin-bottom: 25px;
            overflow: hidden;
        }

        .section-header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 15px 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section-content {
            padding: 20px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }

        .info-item {
            display: flex;
            flex-direction: column;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }

        .info-label {
            font-weight: 600;
            color: var(--gray);
            font-size: 0.9rem;
            margin-bottom: 5px;
        }

        .info-value {
            font-size: 1rem;
        }

        .threat-level {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
        }

        .threat-high {
            background-color: rgba(230, 57, 70, 0.1);
            color: var(--danger);
        }

        .threat-medium {
            background-color: rgba(247, 37, 133, 0.1);
            color: var(--warning);
        }

        .threat-low {
            background-color: rgba(76, 201, 240, 0.1);
            color: var(--success);
        }

        .threat-clean {
            background-color: rgba(67, 97, 238, 0.1);
            color: var(--primary);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: #f8f9fa;
            border-radius: var(--border-radius);
            padding: 15px;
            text-align: center;
        }

        .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.9rem;
            color: var(--gray);
        }

        .error-message {
            background-color: rgba(230, 57, 70, 0.1);
            color: var(--danger);
            padding: 15px;
            border-radius: var(--border-radius);
            margin-bottom: 20px;
            text-align: center;
        }

        .online-search-output {
            background: #f8f9fa;
            border-radius: var(--border-radius);
            padding: 15px;
            margin-top: 15px;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 0.9rem;
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid #e9ecef;
        }

        .search-result-item {
            background: white;
            border-radius: var(--border-radius);
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid var(--primary);
        }

        .search-result-title {
            font-weight: 600;
            margin-bottom: 8px;
        }

        .search-result-link {
            color: var(--primary);
            font-size: 0.85rem;
            margin-bottom: 8px;
            word-break: break-all;
        }

        .search-result-snippet {
            color: var(--gray);
            font-size: 0.9rem;
            line-height: 1.4;
        }

        .search-result-meta {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 0.8rem;
            color: var(--gray);
        }

        footer {
            text-align: center;
            padding: 20px;
            color: var(--gray);
            font-size: 0.9rem;
            margin-top: 30px;
        }

        @media (max-width: 768px) {
            .info-grid, .stats-grid {
                grid-template-columns: 1fr;
            }
            
            h1 {
                font-size: 2rem;
            }
        }
    """

def generate_basic_info_html(basic_info):
    """Generate HTML for basic information section"""
    classification = basic_info["Classification"]
    
    classification_summary = []
    if classification['Bogon']:
        classification_summary.append("BOGON (Non-routable)")
    if classification['Private']:
        classification_summary.append("Private Range")
    if classification['Loopback']:
        classification_summary.append("Loopback")
    if classification['Global']:
        classification_summary.append("Public Range")
    
    classification_html = "<br>".join([f"<span>{item}</span>" for item in classification_summary])
    
    return f"""
        <div class="section">
            <div class="section-header">
                <h2>Basic Information</h2>
            </div>
            <div class="section-content">
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">IP Address</span>
                        <span class="info-value">{basic_info['IP Address']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">IP Version</span>
                        <span class="info-value">{basic_info['IP Version']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Reverse DNS</span>
                        <span class="info-value">{basic_info['Reverse DNS']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Type</span>
                        <span class="info-value">{'Public' if classification['Global'] else 'Private'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Bogon</span>
                        <span class="info-value">{'Yes' if classification['Bogon'] else 'No'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Private</span>
                        <span class="info-value">{'Yes' if classification['Private'] else 'No'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Loopback</span>
                        <span class="info-value">{'Yes' if classification['Loopback'] else 'No'}</span>
                    </div>
                </div>
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: var(--border-radius);">
                    <h3 style="margin-bottom: 10px;">Classification Summary</h3>
                    {classification_html}
                </div>
            </div>
        </div>
    """

def generate_network_info_html(network_info):
    """Generate HTML for network information section"""
    
    # ASN Information
    asn_html = ""
    if "Error" not in network_info["ASN"]:
        asn_data = network_info["ASN"]
        asn_html = f"""
            <div style="margin-bottom: 25px;">
                <h3>ASN Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">AS Number</span>
                        <span class="info-value">{asn_data.get('AS Number', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Organization</span>
                        <span class="info-value">{asn_data.get('Organization', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Network Range</span>
                        <span class="info-value">{asn_data.get('Network Range', 'N/A')}</span>
                    </div>
                </div>
            </div>
        """
    else:
        asn_html = """
            <div style="margin-bottom: 25px;">
                <h3>ASN Information</h3>
                <div class="info-item">
                    <span class="info-value">ASN information not available</span>
                </div>
            </div>
        """
    
    # RDAP Information
    rdap_html = ""
    if "Error" not in network_info["RDAP"]:
        rdap_data = network_info["RDAP"]
        rdap_html = f"""
            <div>
                <h3>RDAP Registration</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Registry</span>
                        <span class="info-value">{rdap_data.get('RIR', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Network Handle</span>
                        <span class="info-value">{rdap_data.get('Network Handle', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Network Name</span>
                        <span class="info-value">{rdap_data.get('Network Name', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">IP Range</span>
                        <span class="info-value">{rdap_data.get('IP Range', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">CIDR</span>
                        <span class="info-value">{rdap_data.get('CIDR', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Country</span>
                        <span class="info-value">{rdap_data.get('Country', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Status</span>
                        <span class="info-value">{rdap_data.get('Status', 'N/A')}</span>
                    </div>
                </div>
            </div>
        """
    else:
        rdap_html = """
            <div>
                <h3>RDAP Registration</h3>
                <div class="info-item">
                    <span class="info-value">RDAP information not available</span>
                </div>
            </div>
        """
    
    return f"""
        <div class="section">
            <div class="section-header">
                <h2>Network Information</h2>
            </div>
            <div class="section-content">
                {asn_html}
                {rdap_html}
            </div>
        </div>
    """

def generate_reputation_html(network_info):
    """Generate HTML for reputation analysis section"""
    
    # AbuseIPDB Information
    abuse_html = ""
    if "Error" not in network_info["AbuseIPDB"]:
        abuse_data = network_info["AbuseIPDB"]
        
        # Determine threat level class
        threat_class = "threat-clean"
        if "HIGH" in abuse_data.get('threat_level', ''):
            threat_class = "threat-high"
        elif "MEDIUM" in abuse_data.get('threat_level', ''):
            threat_class = "threat-medium"
        elif "LOW" in abuse_data.get('threat_level', ''):
            threat_class = "threat-low"
        
        abuse_html = f"""
            <div style="margin-bottom: 25px;">
                <h3>AbuseIPDB Analysis</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Threat Level</span>
                        <span class="info-value"><span class="threat-level {threat_class}">{abuse_data.get('threat_level', 'N/A')}</span></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Abuse Confidence</span>
                        <span class="info-value">{abuse_data.get('abuse_confidence_score', 'N/A')}%</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Total Reports</span>
                        <span class="info-value">{abuse_data.get('total_reports', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Distinct Users</span>
                        <span class="info-value">{abuse_data.get('distinct_users', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Whitelisted</span>
                        <span class="info-value">{'Yes' if abuse_data.get('is_whitelisted') else 'No'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Country</span>
                        <span class="info-value">{abuse_data.get('country_name', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">ISP</span>
                        <span class="info-value">{abuse_data.get('isp', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Usage Type</span>
                        <span class="info-value">{abuse_data.get('usage_type', 'N/A')}</span>
                    </div>
                </div>
            </div>
        """
    else:
        abuse_html = """
            <div style="margin-bottom: 25px;">
                <h3>AbuseIPDB Analysis</h3>
                <div class="info-item">
                    <span class="info-value">AbuseIPDB information not available</span>
                </div>
            </div>
        """
    
    # VirusTotal Information
    vt_html = ""
    if "error" not in network_info["VirusTotal"]:
        vt_data = network_info["VirusTotal"]
        stats = vt_data.get('last_analysis_stats', {})
        
        total = sum(stats.values()) if stats else 0
        threat_percentage = ((stats.get('malicious', 0) + stats.get('suspicious', 0)) / total * 100) if total > 0 else 0
        
        vt_html = f"""
            <div>
                <h3>VirusTotal Analysis</h3>
                <div class="stats-grid" style="margin-bottom: 20px;">
                    <div class="stat-card">
                        <div class="stat-value">{stats.get('harmless', 0)}</div>
                        <div class="stat-label">Harmless</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{stats.get('malicious', 0)}</div>
                        <div class="stat-label">Malicious</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{stats.get('suspicious', 0)}</div>
                        <div class="stat-label">Suspicious</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{threat_percentage:.1f}%</div>
                        <div class="stat-label">Threat Level</div>
                    </div>
                </div>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Reputation Score</span>
                        <span class="info-value">{vt_data.get('reputation', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">AS Owner</span>
                        <span class="info-value">{vt_data.get('as_owner', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">ASN</span>
                        <span class="info-value">{vt_data.get('asn', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Country</span>
                        <span class="info-value">{vt_data.get('country', 'N/A')}</span>
                    </div>
                </div>
            </div>
        """
    else:
        vt_html = """
            <div>
                <h3>VirusTotal Analysis</h3>
                <div class="info-item">
                    <span class="info-value">VirusTotal information not available</span>
                </div>
            </div>
        """
    
    return f"""
        <div class="section">
            <div class="section-header">
                <h2>Reputation Analysis</h2>
            </div>
            <div class="section-content">
                {abuse_html}
                {vt_html}
            </div>
        </div>
    """

def generate_online_search_html(online_search_info):
    """Generate HTML for online search section"""
    if not online_search_info or not online_search_info.get("success"):
        error_msg = online_search_info.get("error", "Online search not performed") if online_search_info else "Online search not performed"
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>Online Search</h2>
            </div>
            <div class="section-content">
                <div class="error-message">
                    Online Search Error: {error_msg}
                </div>
            </div>
        </div>
        """
    
    output = online_search_info.get("output", "No results")
    raw_results = online_search_info.get("raw_results", [])
    results_count = online_search_info.get("results_count", 0)
    
    # Generate detailed results HTML if we have raw results
    detailed_results_html = ""
    if raw_results:
        detailed_results_html = "<h3>Detailed Search Results</h3>"
        for i, result in enumerate(raw_results[:10], 1):  # Show first 10 results
            snippet = result.get("snippet", "No snippet available")
            if len(snippet) > 150:
                snippet = snippet[:150] + "..."
            
            detailed_results_html += f"""
                <div class="search-result-item">
                    <div class="search-result-title">{result.get('title', 'No Title')}</div>
                    <div class="search-result-link"><a href="{result.get('link', '#')}" target="_blank">{result.get('link', 'No URL')}</a></div>
                    <div class="search-result-snippet">{snippet}</div>
                    <div class="search-result-meta">
                        <span>Query: {result.get('query', 'N/A')}</span>
                        <span>Found: {result.get('searchDate', 'N/A')[:16]}</span>
                    </div>
                </div>
            """
    
    return f"""
        <div class="section">
            <div class="section-header">
                <h2>Online Search</h2>
            </div>
            <div class="section-content">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{results_count}</div>
                        <div class="stat-label">Total Mentions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(set(r['query'] for r in raw_results))}</div>
                        <div class="stat-label">Search Variations</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(set(r['link'] for r in raw_results))}</div>
                        <div class="stat-label">Unique Domains</div>
                    </div>
                </div>
                
                <h3>Summary</h3>
                <div class="online-search-output">
{output}
                </div>
                
                {detailed_results_html}
            </div>
        </div>
    """

def generate_summary_html(results):
    """Generate HTML for summary section"""
    basic_info = results["basic_info"]
    network_info = results["network_info"]
    
    vt_stats = network_info["VirusTotal"].get('last_analysis_stats', {}) if "error" not in network_info["VirusTotal"] else {}
    vt_malicious = vt_stats.get('malicious', 0)
    vt_suspicious = vt_stats.get('suspicious', 0)
    
    abuse_score = network_info["AbuseIPDB"].get('abuse_confidence_score', 0) if "Error" not in network_info["AbuseIPDB"] else 0
    
    online_search_count = network_info.get("OnlineSearch", {}).get("results_count", 0)
    
    # Determine overall threat level
    if abuse_score >= 80 or vt_malicious > 5:
        overall_threat = "HIGH THREAT"
        threat_class = "threat-high"
    elif abuse_score >= 50 or vt_malicious > 0 or vt_suspicious > 2:
        overall_threat = "MEDIUM THREAT"
        threat_class = "threat-medium"
    else:
        overall_threat = "LOW THREAT"
        threat_class = "threat-low"
    
    return f"""
        <div class="section">
            <div class="section-header">
                <h2>Analysis Summary</h2>
            </div>
            <div class="section-content">
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">IP Address</span>
                        <span class="info-value">{basic_info['IP Address']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Overall Threat Level</span>
                        <span class="info-value"><span class="threat-level {threat_class}">{overall_threat}</span></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Organization</span>
                        <span class="info-value">{network_info['ASN'].get('Organization', 'Unknown') if 'Error' not in network_info['ASN'] else 'Unknown'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Country</span>
                        <span class="info-value">{network_info['RDAP'].get('Country', network_info['AbuseIPDB'].get('country_name', 'Unknown') if 'Error' not in network_info['AbuseIPDB'] else 'Unknown')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Registry</span>
                        <span class="info-value">{network_info['RDAP'].get('RIR', 'Unknown') if 'Error' not in network_info['RDAP'] else 'Unknown'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Abuse Confidence</span>
                        <span class="info-value">{abuse_score}%</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">VirusTotal Detections</span>
                        <span class="info-value">{vt_malicious} malicious, {vt_suspicious} suspicious</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Online Mentions</span>
                        <span class="info-value">{online_search_count} found</span>
                    </div>
                </div>
            </div>
        </div>
    """

def generate_html_report(results):
    """Generate a complete HTML report from analysis results"""
    
    if "error" in results:
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Analysis - Error</title>
    <style>
        {get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>IP Analysis Tool</h1>
            <p class="subtitle">Comprehensive IP address analysis report</p>
        </header>
        <div class="error-message">
            Error: {results['error']}
        </div>
    </div>
</body>
</html>
        """
    
    basic_info = results["basic_info"]
    network_info = results["network_info"]
    
    # Generate HTML content for each section
    basic_info_html = generate_basic_info_html(basic_info)
    network_info_html = generate_network_info_html(network_info)
    reputation_html = generate_reputation_html(network_info)
    online_search_html = generate_online_search_html(network_info.get("OnlineSearch", {}))
    summary_html = generate_summary_html(results)
    
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Analysis - {basic_info['IP Address']}</title>
    <style>
        {get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>IP Analysis Tool</h1>
            <p class="subtitle">Comprehensive IP address analysis report</p>
        </header>

        {basic_info_html}

        {network_info_html}

        {reputation_html}

        {online_search_html}

        {summary_html}

        <footer>
            <p>IP Analysis Tool &copy; 2023 | Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
    """
    
    return html_template

def save_html_report(results, filename=None):
    """Generate and save HTML report to file"""
    if filename is None:
        ip = results["basic_info"]["IP Address"] if "error" not in results else "error"
        filename = f"ip_analysis_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html_content = generate_html_report(results)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename

# =============================================================================
# FORMATTING & DISPLAY FUNCTIONS
# =============================================================================

def format_timestamp(timestamp):
    """Convert timestamp to readable format"""
    if timestamp:
        try:
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            else:
                # Handle ISO format strings
                return timestamp.replace('T', ' ').replace('Z', ' UTC')
        except:
            return str(timestamp)
    return "N/A"

def format_analysis_stats(stats):
    """Format VirusTotal analysis statistics"""
    if not stats:
        return "No analysis data available"
    
    total = sum(stats.values())
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    
    # Calculate threat percentage
    threat_percentage = ((malicious + suspicious) / total * 100) if total > 0 else 0
    
    return f"""  Harmless: {stats.get('harmless', 0)}
  Suspicious: {suspicious}
  Malicious: {malicious}
  Undetected: {stats.get('undetected', 0)}
  Timeout: {stats.get('timeout', 0)}
  Threat Level: {threat_percentage:.1f}%"""

def format_analysis_results(results):
    """Format engine analysis results"""
    if not results:
        return "  No engine results available"
    
    malicious_results = []
    clean_results = []
    
    for engine, data in results.items():
        category = data.get('category', 'unknown')
        result = data.get('result', 'N/A')
        
        if category in ['malicious', 'suspicious']:
            malicious_results.append(f"    {engine}: {result}")
        elif category == 'harmless':
            clean_results.append(f"    {engine}: Clean")
        else:
            clean_results.append(f"    {engine}: {result}")
    
    output = []
    if malicious_results:
        output.append("  MALICIOUS/SUSPICIOUS DETECTIONS:")
        output.extend(malicious_results[:8])  # Show first 8 malicious results
        if len(malicious_results) > 8:
            output.append(f"    ... and {len(malicious_results) - 8} more")
    
    if not malicious_results and clean_results:
        output.append("  All engines report clean")
    
    return '\n'.join(output)

def format_passive_dns(passive_dns):
    """Format passive DNS records"""
    if not passive_dns:
        return "  No passive DNS records found"
    
    formatted = []
    for record in passive_dns[:8]:  # Show first 8 records
        hostname = record.get('hostname', 'N/A')
        date = format_timestamp(record.get('date', ''))
        formatted.append(f"  {hostname} (Last seen: {date})")
    
    if len(passive_dns) > 8:
        formatted.append(f"  ... and {len(passive_dns) - 8} more records")
    
    return '\n'.join(formatted)

def print_section(title, data, indent=0):
    """Print a section with formatted output"""
    indent_str = " " * indent
    print(f"\n{'='*60}")
    print(f" {title.upper()}")
    print(f"{'='*60}")
    
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict) and key == "Contacts":
                print(f"\n{indent_str} {key}:")
                for role, contacts in value.items():
                    if contacts:
                        print(f"{indent_str}  {role.upper()}:")
                        for contact in contacts:
                            for field, field_value in contact.items():
                                if field_value:
                                    print(f"{indent_str}    {field}: {field_value}")
                            print(f"{indent_str}    {'─'*40}")
            elif isinstance(value, dict) and key == "Timeline":
                print(f"\n{indent_str} {key}:")
                for event, date in value.items():
                    print(f"{indent_str}  {event.replace('_', ' ').title()}: {date}")
            elif isinstance(value, list):
                if value:
                    print(f"{indent_str} {key}:")
                    for item in value[:5]:
                        print(f"{indent_str}  - {item}")
                    if len(value) > 5:
                        print(f"{indent_str}  ... and {len(value) - 5} more")
            elif value is not None and value != "":
                print(f"{indent_str} {key}: {value}")
    else:
        print(f"{indent_str}{data}")

def format_abuseipdb_report(abuse_data):
    """Format AbuseIPDB data for display"""
    if "Error" in abuse_data:
        return f"  {abuse_data['Error']}"
    
    output = []
    
    # Threat Assessment
    confidence = abuse_data.get('abuse_confidence_score', 0)
    threat_level = abuse_data.get('threat_level', 'UNKNOWN')
    output.append(f"  Threat Level: {threat_level}")
    output.append(f"  Abuse Confidence Score: {confidence}%")
    output.append(f"  Total Reports: {abuse_data.get('total_reports', 0)}")
    output.append(f"  Distinct Users: {abuse_data.get('distinct_users', 0)}")
    output.append(f"  Whitelisted: {'Yes' if abuse_data.get('is_whitelisted') else 'No'}")
    output.append(f"  TOR Exit Node: {'Yes' if abuse_data.get('is_tor') else 'No'}")
    
    # Category Breakdown
    categories = abuse_data.get('category_breakdown', {})
    if categories:
        output.append(f"\n  Abuse Categories:")
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]:
            output.append(f"    {category}: {count} reports")
    
    # Recent Reports
    recent_reports = abuse_data.get('recent_reports', [])
    if recent_reports:
        output.append(f"\n  Recent Reports:")
        for i, report in enumerate(recent_reports[:3], 1):
            output.append(f"    {i}. {report['date'][:10]} - {report['reporter_country']}")
            if report['comment']:
                comment_preview = report['comment'][:80] + "..." if len(report['comment']) > 80 else report['comment']
                output.append(f"       \"{comment_preview}\"")
            if report['categories']:
                output.append(f"       Categories: {', '.join(report['categories'][:3])}")
    
    return '\n'.join(output)

def display_online_search_results(online_search_info, ip):
    """Display online search results in console"""
    if not online_search_info or not online_search_info.get("success"):
        error_msg = online_search_info.get("error", "Online search not performed") if online_search_info else "Online search not performed"
        print(f"\nOnline Search: {error_msg}")
        return
    
    output = online_search_info.get("output", "No results")
    results_count = online_search_info.get("results_count", 0)
    raw_results = online_search_info.get("raw_results", [])
    
    print(f"\n{'#'*80}")
    print(f"ONLINE SEARCH RESULTS")
    print(f"{'#'*80}")
    
    # Display summary statistics
    print(f"\nSEARCH SUMMARY:")
    print(f"  Total unique mentions found: {results_count}")
    print(f"  Search variations used: {len(simple_ip_variations(ip))}")
    print(f"  Unique domains: {len(set(r['link'] for r in raw_results))}")
    
    # Display all results in detail
    if raw_results:
        print(f"\nALL MENTIONS FOUND ({len(raw_results)} total):")
        print(f"{'='*80}")
        
        # Group by query type for better organization
        query_groups = {}
        for result in raw_results:
            query = result['query']
            if query not in query_groups:
                query_groups[query] = []
            query_groups[query].append(result)
        
        # Display results grouped by query
        for query, query_results in query_groups.items():
            print(f"\nQUERY: '{query}' ({len(query_results)} results)")
            print(f"{'-'*60}")
            
            for i, result in enumerate(query_results, 1):
                print(f"\n  {i}. {result['title']}")
                print(f"     URL: {result['link']}")
                
                snippet = result.get('snippet', 'No description available')
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                print(f"     Description: {snippet}")
                
                print(f"     Found: {result.get('searchDate', 'Unknown date')[:16]}")
                print(f"     {'─'*50}")
        
        # Generate separate online search HTML report
        html_filename = generate_online_search_html_report(ip, raw_results)
        print(f"\nOnline search HTML report saved: {html_filename}")
    
    else:
        print(f"\nNo online mentions found for this IP address.")
        print("   This could mean:")
        print("   The IP is not publicly mentioned anywhere")
        print("   The IP is too new to be indexed")
        print("   The IP is in a private range")
        print("   No search results matched our criteria")

# =============================================================================
# MAIN ANALYSIS FUNCTIONS
# =============================================================================

def perform_comprehensive_analysis(ip):
    """Perform all analysis types and return consolidated results"""
    print(f"\nStarting comprehensive analysis for: {ip}")
    
    # Basic IP Information
    valid, ip_obj = validate_ip(ip)
    if not valid:
        return {"error": "Invalid IP address"}
    
    classification = classify_ip(ip_obj)
    reverse_dns = reverse_dns_lookup(ip)
    
    # External lookups
    print("Querying ASN database...")
    asn_info = lookup_asn(ip)
    
    print("Querying RDAP databases...")
    rdap_info = rdap_lookup(ip)
    
    print("Querying AbuseIPDB...")
    abuseipdb_info = abuseipdb_lookup(ip)
    
    print("Querying VirusTotal...")
    vt_info = vt_ip_lookup(ip)
    
    # Online Search
    print("Performing online search...")
    online_search_info = online_search_ip(ip)
    
    # Consolidate results
    consolidated = {
        "basic_info": {
            "IP Address": ip,
            "IP Version": classification["IP Version"],
            "Reverse DNS": reverse_dns.get("Hostname", "Not found"),
            "Classification": classification
        },
        "network_info": {
            "ASN": asn_info,
            "RDAP": rdap_info,
            "AbuseIPDB": abuseipdb_info,
            "VirusTotal": vt_info,
            "OnlineSearch": online_search_info
        }
    }
    
    return consolidated

def display_comprehensive_report(results):
    """Display all analysis results in organized sections"""
    if "error" in results:
        print(f"\nError: {results['error']}")
        return
    
    basic_info = results["basic_info"]
    network_info = results["network_info"]
    ip = basic_info['IP Address']
    
    print(f"\n{'#'*80}")
    print(f"COMPREHENSIVE IP ANALYSIS REPORT")
    print(f"{'#'*80}")
    
    # BASIC INFORMATION SECTION
    print_section("Basic Information", basic_info)
    
    # IP CLASSIFICATION SUMMARY
    classification = basic_info["Classification"]
    print(f"\nIP CLASSIFICATION SUMMARY:")
    print(f"  Type: {'Public' if classification['Global'] else 'Private'}")
    print(f"  Version: {classification['IP Version']}")
    if classification['Bogon']:
        print(f"  BOGON (Non-routable)")
    if classification['Private']:
        print(f"  Private Range")
    if classification['Loopback']:
        print(f"  Loopback")
    
    # NETWORK INFORMATION SECTION
    print(f"\n{'#'*80}")
    print(f"NETWORK INFORMATION")
    print(f"{'#'*80}")
    
    # ASN Information
    asn_info = network_info["ASN"]
    if "Error" not in asn_info:
        print_section("ASN Information", asn_info)
    
    # RDAP Information
    rdap_info = network_info["RDAP"]
    if "Error" not in rdap_info:
        print_section("RDAP Registration", {
            "Registry": rdap_info.get("RIR", ""),
            "Network Handle": rdap_info.get("Network Handle", ""),
            "Network Name": rdap_info.get("Network Name", ""),
            "IP Range": rdap_info.get("IP Range", ""),
            "CIDR": rdap_info.get("CIDR", ""),
            "Country": rdap_info.get("Country", ""),
            "Status": rdap_info.get("Status", "")
        })
        
        if rdap_info.get("Contacts"):
            print_section("RDAP Contacts", {"Contacts": rdap_info["Contacts"]})
        
        if rdap_info.get("Timeline"):
            print_section("RDAP Timeline", {"Timeline": rdap_info["Timeline"]})
    
    # ABUSEIPDB REPUTATION SECTION
    print(f"\n{'#'*80}")
    print(f"ABUSEIPDB REPUTATION ANALYSIS")
    print(f"{'#'*80}")
    
    abuse_data = network_info["AbuseIPDB"]
    if "Error" not in abuse_data:
        print(format_abuseipdb_report(abuse_data))
    else:
        print(f"  {abuse_data['Error']}")
    
    # VIRUSTOTAL THREAT INTELLIGENCE
    vt_info = network_info["VirusTotal"]
    if "error" not in vt_info:
        print(f"\n{'#'*80}")
        print(f"THREAT INTELLIGENCE (VIRUSTOTAL)")
        print(f"{'#'*80}")
        
        # Threat Assessment
        stats = vt_info.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        print(f"\nTHREAT ASSESSMENT:")
        print(format_analysis_stats(stats))
        
        # Detection Details
        if malicious > 0 or suspicious > 0:
            print(f"\nDETECTION DETAILS:")
            print(format_analysis_results(vt_info.get('last_analysis_results', {})))
        
        # Network Context
        print(f"\nNETWORK CONTEXT:")
        print(f"  AS Owner: {vt_info.get('as_owner', 'N/A')}")
        print(f"  ASN: {vt_info.get('asn', 'N/A')}")
        print(f"  Country: {vt_info.get('country', 'N/A')}")
        print(f"  Registry: {vt_info.get('regional_internet_registry', 'N/A')}")
        print(f"  JARM: {vt_info.get('jarm', 'N/A')}")
        print(f"  Tags: {', '.join(vt_info.get('tags', [])) or 'None'}")
        
        # Passive DNS
        passive_dns = vt_info.get('passive_dns', [])
        if passive_dns:
            print(f"\nPASSIVE DNS RECORDS ({len(passive_dns)} total):")
            print(format_passive_dns(passive_dns))
        
        # Related Domains
        related_domains = vt_info.get('related_domains', [])
        if related_domains:
            print(f"\nRELATED DOMAINS ({len(related_domains)} total):")
            for domain in related_domains[:5]:
                print(f"  {domain}")
            if len(related_domains) > 5:
                print(f"  ... and {len(related_domains) - 5} more")
        
        # Timestamps
        print(f"\nLAST UPDATED:")
        print(f"  VirusTotal: {format_timestamp(vt_info.get('last_modification_date'))}")
        print(f"  WHOIS: {format_timestamp(vt_info.get('whois_date'))}")
    
    # ONLINE SEARCH SECTION
    online_search_info = network_info.get("OnlineSearch", {})
    display_online_search_results(online_search_info, ip)
    
    # FINAL SUMMARY
    print(f"\n{'#'*80}")
    print(f"ANALYSIS SUMMARY")
    print(f"{'#'*80}")
    
    # Determine overall threat level
    vt_stats = network_info["VirusTotal"].get('last_analysis_stats', {})
    vt_malicious = vt_stats.get('malicious', 0)
    vt_suspicious = vt_stats.get('suspicious', 0)
    
    abuse_score = network_info["AbuseIPDB"].get('abuse_confidence_score', 0)
    online_search_count = online_search_info.get("results_count", 0) if online_search_info else 0
    
    # Combined threat assessment
    if abuse_score >= 80 or vt_malicious > 5:
        overall_threat = "HIGH THREAT"
    elif abuse_score >= 50 or vt_malicious > 0 or vt_suspicious > 2:
        overall_threat = "MEDIUM THREAT"
    else:
        overall_threat = "LOW THREAT"
    
    print(f"IP: {basic_info['IP Address']}")
    print(f"Overall Threat Level: {overall_threat}")
    print(f"Organization: {network_info['ASN'].get('Organization', 'Unknown')}")
    print(f"Country: {network_info['RDAP'].get('Country', network_info['AbuseIPDB'].get('country_name', 'Unknown'))}")
    print(f"Registry: {network_info['RDAP'].get('RIR', 'Unknown')}")
    print(f"Abuse Confidence: {abuse_score}%")
    print(f"VirusTotal Detections: {vt_malicious} malicious, {vt_suspicious} suspicious")
    print(f"Online Mentions: {online_search_count} found")

# =============================================================================
# MODIFIED MAIN EXECUTION WITH HTML OUTPUT
# =============================================================================

def print_cyber_banner():
    banner = r"""
    ██╗██████╗     ██████╗ ██████╗  ██████╗ ███████╗██╗██╗     ███████╗██████╗ 
    ██║██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██║██║     ██╔════╝██╔══██╗
    ██║██████╔╝    ██████╔╝██████╔╝██║   ██║█████╗  ██║██║     █████╗  ██████╔╝
    ██║██╔═══╝     ██╔═══╝ ██╔══██╗██║   ██║██╔══╝  ██║██║     ██╔══╝  ██╔══██╗
    ██║██║         ██║     ██║  ██║╚██████╔╝██║     ██║███████╗███████╗██║  ██║
    ╚═╝╚═╝         ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
    """
    print("\033[1;32m" + banner + "\033[0m")  # Green color

def main():
    print_cyber_banner()

    """Main execution function with HTML output option"""
    print("ENHANCED IP ANALYSIS TOOL")
    print("=" * 50)
    print("Integrates: IP Classification, ASN, RDAP, AbuseIPDB, VirusTotal, Online Search")
    print("=" * 50)

    while True:
        ip_input = input("\nEnter IP address: ").strip()
        
        if ip_input.lower() in ['quit', 'exit', 'q']:
            print("Goodbye!")
            break
        
        if not ip_input:
            continue
        
        # Validate IP
        valid, ip_obj = validate_ip(ip_input)
        if not valid:
            print("Invalid IP address format. Please try again.")
            continue
        
        # Perform comprehensive analysis
        results = perform_comprehensive_analysis(ip_input)
        
        # Ask user if they want HTML output
        html_choice = input("\nGenerate HTML report? (Y/n): ").strip().lower()
        if html_choice in ['y', 'yes', '']:
            filename = save_html_report(results)
            print(f"HTML report generated: {filename}")
        
        # Display console output
        display_comprehensive_report(results)
        
        # Option to show raw data
        show_raw = input("\nShow raw JSON data? (y/N): ").strip().lower()
        if show_raw == 'y':
            filename = input("Enter filename to save (or press Enter for 'raw_data.txt'): ").strip()
            filename = filename if filename else "raw_data.txt"
            
            with open(filename, "w", encoding="utf-8") as file:
                file.write("\n" + "="*60 + "\n")
                file.write("RAW JSON DATA\n")
                file.write("="*60 + "\n")
                file.write(json.dumps(results, indent=2, default=str))
            
            print(f"Data saved to {filename}")
if __name__ == "__main__":
    main()