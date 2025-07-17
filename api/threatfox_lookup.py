import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY")

def lookup_threatfox(ioc: str):
    """
    Lookup an IOC or advanced keyworded query in ThreatFox.
    Supports:
    - ioc:domain.com
    - malware:XWorm
    - tag:TA505
    - hash, IP, or domain
    """
    if not ABUSECH_API_KEY:
        return {"error": "Missing Abuse.ch API key."}

    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "User-Agent": "ai-soc-agent/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Auth-Key": ABUSECH_API_KEY
    }

    payload = {
        "query": "search_ioc" if not ioc.startswith((
            "ioc:", "malware:", "tag:", "uuid:", "threat_type:"
        )) else "search_advanced",
        "search_term": ioc
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        print(f"ThreatFox API Response Status: {response.status_code}")
        print(f"ThreatFox API Response: {response.text[:500]}...")
        
        if response.status_code == 200:
            data = response.json()
            print(f"ThreatFox Data: {data}")
            
            if data.get("query_status") == "ok":
                results = data.get("data", [])
                if results:
                    return results
                else:
                    return {"message": "No ThreatFox results found."}
            elif data.get("query_status") == "no_result":
                return {"message": "No ThreatFox results found."}
            else:
                return {
                    "status": data.get("query_status"),
                    "reason": data.get("reason", "No reason provided.")
                }
        elif response.status_code == 401:
            return {"error": "HTTP 401 Unauthorized. Check API key and headers."}
        else:
            return {"error": f"HTTP {response.status_code}", "details": response.text}
    except Exception as e:
        print(f"ThreatFox Exception: {str(e)}")
        return {"error": str(e)}

def format_threatfox(data):
    """Format ThreatFox data for consistent output"""
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
            formatted.append({
                "IOC ID": entry.get("id"),
                "IOC": entry.get("ioc"),
                "IOC Type": entry.get("ioc_type"),
                "Threat Type": entry.get("threat_type"),
                "Malware": entry.get("malware"),
                "Malware Alias": entry.get("malware_alias"),
                "Confidence Level": f"{entry.get('confidence')}%" if entry.get("confidence") is not None else None,
                "ASN": entry.get("asn"),
                "Country": entry.get("country"),
                "First Seen": entry.get("first_seen"),
                "Last Seen": entry.get("last_seen"),
                "UUID": entry.get("uuid"),
                "Reporter": entry.get("reporter"),
                "Reward": f"{entry.get('credits')} credits from {entry.get('reporter', 'anonymous')}",
                "Tags": ", ".join(entry.get("tags", [])) if isinstance(entry.get("tags"), list) else entry.get("tags"),
                "Reference": entry.get("reference"),
            })
        return formatted

    return {"message": "No matching IOCs found."}