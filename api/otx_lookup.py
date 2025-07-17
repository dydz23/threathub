import os
import re
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

def sanitize_ioc(ioc: str, ioc_type: str) -> str:
    """
    For URL inputs, extract domain only since OTX does not support full URLs.
    """
    if ioc_type == "url":
        parsed = urlparse(ioc)
        return parsed.hostname or ioc  # fallback
    return ioc

def lookup_otx(ioc: str, ioc_type: str):
    if not OTX_API_KEY:
        return {"error": "Missing OTX API key."}

    ioc = sanitize_ioc(ioc, ioc_type)
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    if ioc_type == "ip":
        url = f"{base_url}/IPv4/{ioc}/general"
    elif ioc_type == "domain" or ioc_type == "url":
        url = f"{base_url}/domain/{ioc}/general"
    elif ioc_type == "hash":
        url = f"{base_url}/file/{ioc}/general"
    else:
        return {"error": f"Unsupported IOC type for OTX: {ioc_type}"}

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "User-Agent": "ai-soc-agent"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"OTX HTTP {response.status_code}",
                "details": response.text
            }
    except requests.RequestException as e:
        return {"error": f"Request failed", "details": str(e)}
    except Exception as e:
        return {"error": "Unexpected error", "details": str(e)}
