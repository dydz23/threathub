from datetime import datetime

def format_timestamp(ts):
    if not ts:
        return None
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ts  # fallback if already formatted

def format_virustotal(data):
    """Enhanced VirusTotal formatting with comprehensive details"""
    if not isinstance(data, dict):
        return {"message": "Invalid VT data format."}
    if "error" in data:
        return data
    if "message" in data:
        return {"message": data["message"]}

    if "details" in data:
        attributes = data["details"].get("data", {}).get("attributes", {})
        vt_id = data["details"].get("data", {}).get("id")
    else:
        attributes = data.get("data", {}).get("attributes", {})
        vt_id = data.get("data", {}).get("id")

    result = {
        "ID": vt_id,
        "Reputation": attributes.get("reputation"),
        "Type": attributes.get("type_description"),
        "Meaningful Name": attributes.get("meaningful_name"),
    }

    # Analysis statistics
    stats = attributes.get("last_analysis_stats", {})
    if stats:
        result["Detection Ratio"] = f"{stats.get('malicious', 0)}/{stats.get('malicious', 0) + stats.get('harmless', 0) + stats.get('undetected', 0) + stats.get('suspicious', 0)}"
        result["Malicious Detections"] = stats.get("malicious", 0)
        result["Suspicious Detections"] = stats.get("suspicious", 0)
        result["Harmless Detections"] = stats.get("harmless", 0)
        result["Undetected"] = stats.get("undetected", 0)
        result["Timeout"] = stats.get("timeout", 0)

    # Categories from different engines
    categories = attributes.get("categories")
    if categories:
        result["Categories"] = categories

    # Timestamps
    if "first_submission_date" in attributes:
        result["First Submission"] = format_timestamp(attributes["first_submission_date"])
    if "last_analysis_date" in attributes:
        result["Last Analysis"] = format_timestamp(attributes["last_analysis_date"])
    if "last_modification_date" in attributes:
        result["Last Modified"] = format_timestamp(attributes["last_modification_date"])

    # Network information
    if "network" in attributes:
        result["Network"] = attributes.get("network")
    if "country" in attributes:
        result["Country"] = attributes.get("country")
    if "asn" in attributes:
        result["ASN"] = attributes.get("asn")
    if "as_owner" in attributes:
        result["AS Owner"] = attributes.get("as_owner")

    # Additional file information
    if "size" in attributes:
        result["File Size"] = f"{attributes['size']:,} bytes"
    if "md5" in attributes:
        result["MD5"] = attributes["md5"]
    if "sha1" in attributes:
        result["SHA1"] = attributes["sha1"]
    if "sha256" in attributes:
        result["SHA256"] = attributes["sha256"]
    if "magic" in attributes:
        result["File Magic"] = attributes["magic"]
    if "signature_info" in attributes:
        sig_info = attributes["signature_info"]
        if isinstance(sig_info, dict):
            result["Signature Subject"] = sig_info.get("subject", "N/A")
            result["Signature Issuer"] = sig_info.get("issuer", "N/A")
            result["Signature Valid"] = sig_info.get("verified", "Unknown")

    # Names and aliases
    names = attributes.get("names", [])
    if names:
        result["Known Names"] = names[:5]  # Limit to first 5

    # Sandbox information
    sandbox_verdicts = attributes.get("sandbox_verdicts", {})
    if sandbox_verdicts:
        sandbox_results = []
        for engine, verdict in sandbox_verdicts.items():
            if isinstance(verdict, dict):
                sandbox_results.append(f"{engine}: {verdict.get('category', 'N/A')}")
        if sandbox_results:
            result["Sandbox Verdicts"] = sandbox_results[:3]  # Top 3

    # Flatten related fields if available
    related = data.get("related", {})

    def extract_ids(entries, limit=5):
        return [e.get("id") for e in entries[:limit] if isinstance(e, dict)]

    if "resolutions" in related and related["resolutions"]:
        result["Resolved IPs"] = extract_ids(related["resolutions"])
    if "communicating_files" in related and related["communicating_files"]:
        result["Communicating Files"] = extract_ids(related["communicating_files"])
    if "downloaded_files" in related and related["downloaded_files"]:
        result["Downloaded Files"] = extract_ids(related["downloaded_files"])
    if "contacted_domains" in related and related["contacted_domains"]:
        result["Contacted Domains"] = extract_ids(related["contacted_domains"])
    if "contacted_ips" in related and related["contacted_ips"]:
        result["Contacted IPs"] = extract_ids(related["contacted_ips"])

    return result

def format_abuseipdb(data):
    """Enhanced AbuseIPDB formatting with complete details"""
    if not isinstance(data, dict):
        return data
    if data.get("error"):
        return data
    
    result = {}
    
    # Core information
    if "IP Address" in data:
        result["IP Address"] = data["IP Address"]
    if "Abuse Score" in data:
        result["Abuse Confidence"] = f"{data['Abuse Score']}%"
        
        # Risk assessment based on score
        score = data["Abuse Score"]
        if score >= 75:
            result["Risk Level"] = "High Risk"
        elif score >= 25:
            result["Risk Level"] = "Medium Risk"
        else:
            result["Risk Level"] = "Low Risk"
    
    # Geographic information
    if "Country" in data:
        result["Country Code"] = data["Country"]
    if "ISP" in data:
        result["ISP"] = data["ISP"]
    if "Domain" in data:
        result["Domain"] = data["Domain"]
    if "Usage Type" in data:
        result["Usage Type"] = data["Usage Type"]
    
    # Abuse information
    if "Total Reports" in data:
        result["Total Reports"] = data["Total Reports"]
    if "Last Reported" in data:
        result["Last Reported"] = data["Last Reported"]
    
    # Additional context
    if "⚠️ Resolved Lookup" in data:
        result["Resolution Note"] = data["⚠️ Resolved Lookup"]
    
    return result

def format_shodan(data):
    """Enhanced Shodan formatting with complete details"""
    if not isinstance(data, dict):
        return data
    if data.get("error"):
        return data
    
    result = {}
    
    # Basic information
    if "ip" in data:
        result["IP Address"] = data["ip"]
    if "organization" in data:
        result["Organization"] = data["organization"]
    if "isp" in data:
        result["ISP"] = data["isp"]
    if "os" in data:
        result["Operating System"] = data["os"]
    
    # Location information
    if "country" in data:
        result["Country"] = data["country"]
    if "city" in data:
        result["City"] = data["city"]
    if "region_code" in data:
        result["Region"] = data["region_code"]
    
    # Network information
    if "open_ports" in data and data["open_ports"]:
        result["Open Ports"] = data["open_ports"]
        result["Total Open Ports"] = len(data["open_ports"])
    if "hostnames" in data and data["hostnames"]:
        result["Hostnames"] = data["hostnames"]
    
    # Vulnerability information
    if "vulns" in data and data["vulns"]:
        result["Vulnerabilities"] = data["vulns"]
        result["Vulnerability Count"] = len(data["vulns"])
    
    # Tags and classification
    if "tags" in data and data["tags"]:
        result["Tags"] = data["tags"]
    
    # Last update
    if "last_update" in data:
        result["Last Updated"] = data["last_update"]
    
    return result

def format_otx(data):
    """Enhanced OTX formatting with complete details"""
    if not isinstance(data, dict):
        return data
    if data.get("error"):
        return data
    
    result = {}
    
    # Basic indicator information
    if "indicator" in data:
        result["Indicator"] = data["indicator"]
    if "type" in data:
        result["Type"] = data["type"]
    if "type_title" in data:
        result["Type Description"] = data["type_title"]
    
    # Pulse information
    pulse_info = data.get("pulse_info", {})
    if pulse_info:
        pulses = pulse_info.get("pulses", [])
        if pulses:
            result["Pulse Count"] = len(pulses)
            
            # Extract key pulse information
            pulse_names = []
            pulse_tags = set()
            malware_families = set()
            
            for pulse in pulses[:5]:  # Limit to first 5 pulses
                if pulse.get("name"):
                    pulse_names.append(pulse["name"])
                if pulse.get("tags"):
                    pulse_tags.update(pulse["tags"])
                if pulse.get("malware_families"):
                    for family in pulse["malware_families"]:
                        if isinstance(family, dict) and family.get("display_name"):
                            malware_families.add(family["display_name"])
            
            if pulse_names:
                result["Related Pulses"] = pulse_names
            if pulse_tags:
                result["Associated Tags"] = list(pulse_tags)[:10]  # Limit tags
            if malware_families:
                result["Malware Families"] = list(malware_families)
    
    # General information
    general = data.get("general", {})
    if general:
        if "sections" in general:
            result["Available Sections"] = general["sections"]
        if "whois" in general:
            result["Whois Available"] = "Yes"
        if "reputation" in general:
            result["Reputation"] = general["reputation"]
    
    return result

def format_threatfox(data):
    """Enhanced ThreatFox formatting with complete details"""
    if not data:
        return {"message": "No ThreatFox data returned."}

    if isinstance(data, dict):
        if data.get("error"):
            return data
        if data.get("status") or data.get("message"):
            return {
                "Status": data.get("status"),
                "Message": data.get("message"),
                "Reason": data.get("reason", "No reason provided")
            }

    if isinstance(data, list) and data:
        formatted = []
        for entry in data:
            formatted_entry = {
                "IOC ID": entry.get("id"),
                "IOC Value": entry.get("ioc"),
                "IOC Type": entry.get("ioc_type"),
                "Threat Type": entry.get("threat_type"),
                "Malware Family": entry.get("malware"),
                "Malware Alias": entry.get("malware_alias"),
            }
            
            # Confidence and reliability
            if entry.get("confidence") is not None:
                formatted_entry["Confidence Level"] = f"{entry.get('confidence')}%"
                confidence = entry.get("confidence")
                if confidence >= 75:
                    formatted_entry["Reliability"] = "High"
                elif confidence >= 50:
                    formatted_entry["Reliability"] = "Medium"
                else:
                    formatted_entry["Reliability"] = "Low"
            
            # Network information
            if entry.get("asn"):
                formatted_entry["ASN"] = entry.get("asn")
            if entry.get("country"):
                formatted_entry["Country"] = entry.get("country")
            
            # Timeline
            if entry.get("first_seen"):
                formatted_entry["First Seen"] = entry.get("first_seen")
            if entry.get("last_seen"):
                formatted_entry["Last_seen"] = entry.get("last_seen")
            
            # Submission details
            if entry.get("uuid"):
                formatted_entry["UUID"] = entry.get("uuid")
            if entry.get("reporter"):
                formatted_entry["Reporter"] = entry.get("reporter")
            if entry.get("credits"):
                formatted_entry["Credits"] = f"{entry.get('credits')} credits"
            
            # Tags and references
            tags = entry.get("tags", [])
            if isinstance(tags, list) and tags:
                formatted_entry["Tags"] = ", ".join(tags)
            elif tags:
                formatted_entry["Tags"] = str(tags)
                
            if entry.get("reference"):
                formatted_entry["Reference"] = entry.get("reference")
            
            formatted.append(formatted_entry)
        
        return formatted

    return {"message": "No matching IOCs found."}

def format_urlhaus(data):
    """Enhanced URLhaus formatting with complete details"""
    if not isinstance(data, dict):
        return data
    if data.get("error"):
        return data
    if data.get("message"):
        return data
    
    result = {}
    
    # Handle search results
    if "results" in data and data["results"]:
        results = []
        for item in data["results"]:
            result_item = {
                "URL": item.get("url"),
                "Host": item.get("host"),
                "Threat Classification": item.get("threat"),
                "Date Added": item.get("date_added"),
                "Reporter": item.get("reporter"),
                "URL Status": item.get("url_status"),
            }
            if item.get("tags"):
                result_item["Tags"] = ", ".join(item["tags"]) if isinstance(item["tags"], list) else item["tags"]
            results.append(result_item)
        return {"results": results, "found": True}
    
    # Handle single payload result
    if data.get("found"):
        if "SHA256" in data:
            result["SHA256 Hash"] = data["SHA256"]
        if "MD5" in data:
            result["MD5 Hash"] = data["MD5"]
        if "File Size" in data:
            result["File Size"] = data["File Size"]
        if "File Type" in data:
            result["File Type"] = data["File Type"]
        if "First Seen" in data:
            result["First Seen"] = data["First Seen"]
        if "Last Seen" in data:
            result["Last Seen"] = data["Last Seen"]
        if "URL Count" in data:
            result["Associated URLs"] = data["URL Count"]
        if "URLs" in data and data["URLs"]:
            result["Sample URLs"] = data["URLs"]
        
        return {**result, "found": True}
    
    return data

def format_malwarebazaar(data):
    """Enhanced MalwareBazaar formatting with complete details"""
    if not isinstance(data, dict):
        return data
    if data.get("error"):
        return data
    if data.get("message"):
        return data
    
    result = {}
    
    # Handle search results
    if "results" in data and data["results"]:
        results = []
        for item in data["results"]:
            result_item = {
                "SHA256 Hash": item.get("SHA256"),
                "File Name": item.get("File Name"),
                "File Type": item.get("File Type"),
                "Malware Signature": item.get("Signature"),
                "File Size": item.get("File Size"),
                "First Seen": item.get("First Seen"),
                "Reporter": item.get("Reporter"),
            }
            if item.get("Tags"):
                result_item["Tags"] = ", ".join(item["Tags"]) if isinstance(item["Tags"], list) else item["Tags"]
            results.append(result_item)
        return {"results": results, "found": True}
    
    # Handle single result
    if data.get("found"):
        if "SHA256" in data:
            result["SHA256 Hash"] = data["SHA256"]
        if "File Name" in data:
            result["File Name"] = data["File Name"]
        if "File Type" in data:
            result["MIME Type"] = data["File Type"]
        if "File Size" in data:
            result["File Size"] = f"{data['File Size']:,} bytes" if isinstance(data["File Size"], int) else data["File Size"]
        if "Signature" in data:
            result["Malware Signature"] = data["Signature"]
        if "Tags" in data:
            tags = data["Tags"]
            result["Tags"] = ", ".join(tags) if isinstance(tags, list) else str(tags)
        if "Delivery Method" in data:
            result["Delivery Method"] = data["Delivery Method"]
        if "First Seen" in data:
            result["First Seen"] = data["First Seen"]
        if "Last Seen" in data:
            result["Last Seen"] = data["Last Seen"]
        if "Reporter" in data:
            result["Reporter"] = data["Reporter"]
        if "Comment" in data and data["Comment"]:
            result["Comment"] = data["Comment"]
        
        # Vendor intelligence
        vendor_intel = data.get("Vendor Detections", {})
        if vendor_intel and isinstance(vendor_intel, dict):
            intel_summary = []
            for vendor, info in vendor_intel.items():
                if isinstance(info, dict):
                    if info.get("verdict") == "MALICIOUS":
                        intel_summary.append(f"{vendor}: {info.get('verdict')}")
                    elif info.get("detection"):
                        intel_summary.append(f"{vendor}: {info.get('detection')}")
            if intel_summary:
                result["Vendor Intelligence"] = intel_summary[:5]  # Limit to 5
        
        return {**result, "found": True}
    
    return data

def format_ipinfo(data):
    """Enhanced IPInfo formatting with complete details"""
    if not isinstance(data, dict):
        return data
    if data.get("error"):
        return data
    
    result = {}
    
    # Basic information
    if "IP" in data:
        result["IP Address"] = data["IP"]
    if "Hostname" in data:
        result["Hostname"] = data["Hostname"]
    
    # Geographic information
    if "City" in data:
        result["City"] = data["City"]
    if "Region" in data:
        result["Region/State"] = data["Region"]
    if "Country" in data:
        result["Country"] = data["Country"]
    
    # Network information
    if "Organization" in data:
        result["Organization"] = data["Organization"]
    if "ASN" in data:
        result["ASN"] = data["ASN"]
    
    # Additional context
    if "⚠️ Resolved Lookup" in data:
        result["Resolution Note"] = data["⚠️ Resolved Lookup"]
    
    return result

def format_urlscan(data):
    """Enhanced URLScan formatting - handled separately in frontend"""
    # URLScan has complex structure handled in frontend
    return data