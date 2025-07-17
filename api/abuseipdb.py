# api/abuseipdb.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip(ip: str, original_domain: str = None):
    if not ABUSEIPDB_API_KEY:
        return {"error": "Missing AbuseIPDB API key."}

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]
            result = {
                "IP Address": data.get("ipAddress"),
                "Abuse Score": data.get("abuseConfidenceScore"),
                "Country": data.get("countryCode"),
                "ISP": data.get("isp", "N/A"),
                "Domain": data.get("domain", "N/A"),
                "Usage Type": data.get("usageType", "N/A"),
                "Total Reports": data.get("totalReports"),
                "Last Reported": data.get("lastReportedAt", "N/A")
            }

            if original_domain:
                result["⚠️ Resolved Lookup"] = f"IP shown was resolved from {original_domain}"

            return result
        else:
            return {"error": f"AbuseIPDB HTTP {response.status_code}", "details": response.text}
    except Exception as e:
        return {"error": str(e)}
