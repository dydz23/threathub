# api/ipinfo_lookup.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()
IPINFO_API_KEY = os.getenv("IPINFO_TOKEN")

def lookup_ipinfo(ip: str, original_domain: str = None):
    if not IPINFO_API_KEY:
        return {"error": "Missing IPinfo API key."}

    url = f"https://ipinfo.io/{ip}/json"
    headers = {
        "Authorization": f"Bearer {IPINFO_API_KEY}"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            result = {
                "IP": data.get("ip"),
                "Hostname": data.get("hostname"),
                "City": data.get("city"),
                "Region": data.get("region"),
                "Country": data.get("country"),
                "Organization": data.get("org"),
                "ASN": data.get("asn", {}).get("asn", "N/A")
            }

            if original_domain:
                result["⚠️ Resolved Lookup"] = f"IP shown was resolved from {original_domain}"

            return result
        else:
            return {"error": f"IPinfo HTTP {response.status_code}", "details": response.text}
    except Exception as e:
        return {"error": str(e)}
