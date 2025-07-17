import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY")

HEADERS = {
    "User-Agent": "ai-soc-agent/1.0",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Auth-Key": ABUSECH_API_KEY
}

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"

def lookup_urlhaus(ioc: str):
    if not ABUSECH_API_KEY:
        return {"error": "Missing Abuse.ch API key for URLHaus."}

    ioc = ioc.strip()

    # 🔍 Search syntax-based (e.g., tag:SocGholish or filetype:doc)
    if ":" in ioc and not re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return _search_urlhaus(ioc)

    # 🧬 Hash lookup uses the payload endpoint
    # Determine hash type and construct payload
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        payload = {"md5_hash": ioc}
    elif re.match(r"^[a-fA-F0-9]{64}$", ioc):
        payload = {"sha256_hash": ioc}
    else:
        return {"error": "Invalid hash format for URLhaus lookup"}

    try:
        # Use the correct payload endpoint
        url = "https://urlhaus-api.abuse.ch/v1/payload/"
        
        # Use form data with Auth-Key header
        headers = {
            "User-Agent": "ai-soc-agent/1.0",
            "Auth-Key": ABUSECH_API_KEY
        }
        
        res = requests.post(url, data=payload, headers=headers, timeout=10)
        
        print(f"URLhaus API URL: {url}")
        print(f"URLhaus API Payload: {payload}")
        print(f"URLhaus API Response Status: {res.status_code}")
        print(f"URLhaus API Response: {res.text[:500]}...")
        
        if res.status_code != 200:
            return {"error": f"HTTP {res.status_code}", "details": res.text}

        data = res.json()
        print(f"URLhaus Data: {data}")
        
        if data.get("query_status") == "ok":
            # URLhaus payload response has different structure
            return {
                "found": True,
                "SHA256": data.get("sha256_hash"),
                "MD5": data.get("md5_hash"),
                "File Size": data.get("file_size"),
                "File Type": data.get("file_type"),
                "First Seen": data.get("firstseen"),
                "Last Seen": data.get("lastseen"),
                "URL Count": len(data.get("urls", [])),
                "URLs": [url.get("url") for url in data.get("urls", [])[:3]]  # First 3 URLs
            }
        elif data.get("query_status") == "no_results":
            return {"message": "No URLhaus results found."}
        else:
            return {
                "status": data.get("query_status"),
                "reason": data.get("reason", "No reason provided.")
            }
    except Exception as e:
        print(f"URLhaus Exception: {str(e)}")
        return {"error": str(e)}

def _search_urlhaus(term: str):
    """Search URLhaus with proper form data"""
    payload = {
        "query": "search",
        "search_term": term
    }
    
    try:
        url = "https://urlhaus-api.abuse.ch/v1/"
        
        # Use form data, not JSON for URLhaus API
        res = requests.post(url, data=payload, headers={
            "User-Agent": "ai-soc-agent/1.0",
            "Auth-Key": ABUSECH_API_KEY
        }, timeout=10)
        
        print(f"URLhaus Search URL: {url}")
        print(f"URLhaus Search Payload: {payload}")
        print(f"URLhaus Search Response Status: {res.status_code}")
        print(f"URLhaus Search Response: {res.text[:500]}...")
        
        if res.status_code != 200:
            return {"error": f"HTTP {res.status_code}", "details": res.text}

        data = res.json()
        print(f"URLhaus Search Data: {data}")
        
        if data.get("query_status") == "ok" and data.get("urls"):
            return {
                "found": True,
                "results": [
                    {
                        "URL": item.get("url"),
                        "Host": item.get("host"),
                        "Threat": item.get("threat"),
                        "Tags": item.get("tags"),
                        "Date Added": item.get("date_added"),
                        "Reporter": item.get("reporter"),
                        "URL Status": item.get("url_status"),
                    }
                    for item in data["urls"][:5]  # Limit to first 5 results
                ]
            }
        elif data.get("query_status") == "no_results":
            return {"message": "No URLhaus search results found."}
        else:
            return {
                "status": data.get("query_status"),
                "reason": data.get("reason", "No data matched.")
            }
    except Exception as e:
        print(f"URLhaus Search Exception: {str(e)}")
        return {"error": str(e)}