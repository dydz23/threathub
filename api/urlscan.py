# api/urlscan.py

import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

HEADERS = {
    "API-Key": URLSCAN_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def wait_for_result(scan_id, timeout=30, interval=5):
    result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    for _ in range(timeout // interval):
        try:
            res = requests.get(result_url, headers=HEADERS, timeout=10)
            if res.status_code == 200:
                return res.json()
        except requests.RequestException:
            pass
        time.sleep(interval)
    return None

def active_scan(url: str):
    if not URLSCAN_API_KEY:
        return {"error": "Missing URLScan API key."}

    payload = {
        "url": url,
        "visibility": "public"
    }

    try:
        post = requests.post("https://urlscan.io/api/v1/scan/", json=payload, headers=HEADERS, timeout=10)
        if post.status_code != 200:
            return {"error": f"URLScan Active HTTP {post.status_code}", "details": post.text}

        scan_id = post.json().get("uuid")
        result = wait_for_result(scan_id)

        if not result:
            return {"error": "URLScan result not ready after timeout."}

        page = result.get("page", {})
        lists = result.get("lists", {})
        task = result.get("task", {})
        verdicts = result.get("verdicts", {}).get("overall", {})

        return {
            "method": "active",
            "summary": {
                "Scan URL": task.get("url"),
                "Scan Time": task.get("time"),
                "Visibility": task.get("visibility"),
                "Verdict Score": verdicts.get("score"),
                "Verdict Tags": ", ".join(verdicts.get("tags", [])),
                "Status": page.get("status"),
                "MIME Type": page.get("mimeType"),
                "Server": page.get("server"),
            },
            "domain_info": {
                "Domain": page.get("domain"),
                "IP": page.get("ip"),
                "ASN": page.get("asn"),
                "ASN Name": page.get("asnname"),
                "Country": page.get("country"),
                "TLS Issuer": page.get("tlsIssuer"),
            },
            "http": {
                "Redirects": [r.get("response", {}).get("url") for r in lists.get("redirects", [])],
                "Indicators": lists.get("verdicts", {}),
                "Behaviors": lists.get("behavior", {}),
            },
            "screenshot": result.get("screenshot"),
            "reportURL": task.get("reportURL"),
            "raw": result
        }

    except Exception as e:
        return {"error": str(e)}

def lookup_urlscan(ioc: str):
    """
    Always use active scan to get fresh data and screenshot.
    """
    if not ioc.startswith("http"):
        ioc = "http://" + ioc  # Normalize for scanning

    return active_scan(ioc)
