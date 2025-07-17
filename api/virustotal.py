# api/virustotal.py

import os
import requests
import base64
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def check_virustotal(ioc: str):
    if not VT_API_KEY:
        return {"error": "Missing VirusTotal API key."}

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    try:
        # 1. Search
        search_url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
        search_response = requests.get(search_url, headers=headers, timeout=10)
        if search_response.status_code != 200:
            return {"error": f"VT Search HTTP {search_response.status_code}", "details": search_response.text}

        search_data = search_response.json()
        if not search_data.get("data"):
            return {"message": "No data found in VirusTotal search."}

        item = search_data["data"][0]
        item_id = item.get("id")
        item_type = item.get("type")

        if not item_id or not item_type:
            return {"message": "Unable to determine ID/type from VT search result."}

        # 2. Main detail query
        base_detail_url = f"https://www.virustotal.com/api/v3/{item_type}s/{item_id}"
        detail_response = requests.get(base_detail_url, headers=headers, timeout=10)
        if detail_response.status_code != 200:
            return {"error": f"VT Detail HTTP {detail_response.status_code}", "details": detail_response.text}

        details = detail_response.json()

        # 3. Enrich with related data (where applicable)
        related_data = {}

        def fetch_relation(relationship):
            url = f"https://www.virustotal.com/api/v3/{item_type}s/{item_id}/relationships/{relationship}"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                return r.json().get("data", [])
            return []

        if item_type == "domain":
            related_data["resolutions"] = fetch_relation("resolutions")
            related_data["communicating_files"] = fetch_relation("communicating_files")
            related_data["downloaded_files"] = fetch_relation("downloaded_files")

        elif item_type == "ip_address":
            related_data["resolutions"] = fetch_relation("resolutions")
            related_data["contacted_domains"] = fetch_relation("contacted_domains")

        elif item_type == "url":
            related_data["downloaded_files"] = fetch_relation("downloaded_files")

        elif item_type == "file":
            related_data["contacted_domains"] = fetch_relation("contacted_domains")
            related_data["contacted_ips"] = fetch_relation("contacted_ips")

        return {
            "details": details,
            "related": related_data
        }

    except Exception as e:
        return {"error": str(e)}
