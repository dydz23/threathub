# api/shodan_lookup.py

import os
import shodan
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
api = shodan.Shodan(SHODAN_API_KEY)

def lookup_shodan(ip):  # 🔁 Renamed to match import in main.py
    if not SHODAN_API_KEY:
        return {"error": "Missing Shodan API key."}

    try:
        host = api.host(ip)
        result = {
            "ip": host.get("ip_str"),
            "organization": host.get("org"),
            "os": host.get("os"),
            "last_update": host.get("last_update"),
            "open_ports": host.get("ports"),
            "hostnames": host.get("hostnames"),
            "country": host.get("country_name"),
            "isp": host.get("isp"),
            "tags": host.get("tags"),
            "vulns": list(host.get("vulns", [])),
        }
        return result
    except shodan.APIError as e:
        return {"error": str(e)}
