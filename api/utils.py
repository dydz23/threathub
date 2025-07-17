import re
from urllib.parse import urlparse
import time
import requests
import ipaddress

def detect_input_type(input_value: str) -> str:
    """
    Enhanced IOC detection supporting all major indicator types
    """
    input_value = input_value.strip()

    # ThreatFox advanced queries
    if input_value.startswith(("ioc:", "tag:", "malware:", "uuid:", "threat_type:")):
        return "threatfox_query"

    # Email addresses
    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", input_value):
        return "email"

    # URLs (various protocols)
    if re.match(r"^(https?|ftp|ftps|sftp|file):\/\/[\w\.-]+(?:\/[\w\.-]*)*(?:\?[^\s]*)?(?:#[^\s]*)?$", input_value):
        return "url"
    
    # URL without protocol
    if re.match(r"^[\w\.-]+\/[\w\.-\/]*(?:\?[^\s]*)?(?:#[^\s]*)?$", input_value) and not re.match(r"^[a-fA-F0-9]{32,}$", input_value):
        return "url_no_protocol"

    # IPv4 addresses
    try:
        ip = ipaddress.IPv4Address(input_value)
        return "ipv4"
    except ipaddress.AddressValueError:
        pass

    # IPv6 addresses
    try:
        ip = ipaddress.IPv6Address(input_value)
        return "ipv6"
    except ipaddress.AddressValueError:
        pass

    # CIDR notation (IPv4 and IPv6)
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$", input_value):
        try:
            ipaddress.IPv4Network(input_value, strict=False)
            return "cidr_ipv4"
        except ipaddress.AddressValueError:
            pass
    
    if re.match(r"^[a-fA-F0-9:]+\/\d{1,3}$", input_value):
        try:
            ipaddress.IPv6Network(input_value, strict=False)
            return "cidr_ipv6"
        except ipaddress.AddressValueError:
            pass

    # Hash types (multiple algorithms)
    if re.match(r"^[a-fA-F0-9]{32}$", input_value):
        return "md5"
    elif re.match(r"^[a-fA-F0-9]{40}$", input_value):
        return "sha1"
    elif re.match(r"^[a-fA-F0-9]{56}$", input_value):
        return "sha224"
    elif re.match(r"^[a-fA-F0-9]{64}$", input_value):
        return "sha256"
    elif re.match(r"^[a-fA-F0-9]{96}$", input_value):
        return "sha384"
    elif re.match(r"^[a-fA-F0-9]{128}$", input_value):
        return "sha512"
    elif re.match(r"^[a-fA-F0-9]{70}$", input_value):
        return "tlsh"
    elif re.match(r"^[a-fA-F0-9]{72}$", input_value):
        return "imphash"
    elif re.match(r"^[a-zA-Z0-9+/]{27}=$", input_value):
        return "ssdeep"

    # Registry keys
    if re.match(r"^HK(EY_)?(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\", input_value, re.IGNORECASE):
        return "registry_key"

    # File paths (Windows)
    if re.match(r"^[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*$", input_value):
        return "file_path_windows"
    
    # File paths (Unix/Linux)
    if re.match(r"^\/(?:[^\/\0]+\/)*[^\/\0]*$", input_value) and len(input_value) > 1:
        return "file_path_unix"

    # Mutex names
    if re.match(r"^(Global\\|Local\\)?[a-zA-Z0-9_\-\.{}]+$", input_value) and len(input_value) > 5:
        # Check if it looks like a mutex (contains typical mutex patterns)
        if any(pattern in input_value.lower() for pattern in ["mutex", "lock", "sync", "global\\", "local\\"]):
            return "mutex"

    # User-Agent strings
    if re.match(r"^Mozilla\/[\d\.]+ \(.*\).*$", input_value) or "User-Agent:" in input_value:
        return "user_agent"

    # Bitcoin addresses
    if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", input_value) or re.match(r"^bc1[a-z0-9]{39,59}$", input_value):
        return "bitcoin_address"

    # CVE identifiers
    if re.match(r"^CVE-\d{4}-\d{4,}$", input_value, re.IGNORECASE):
        return "cve"

    # ASN (Autonomous System Number)
    if re.match(r"^AS\d+$", input_value, re.IGNORECASE):
        return "asn"

    # YARA rule names
    if re.match(r"^rule\s+\w+\s*\{", input_value, re.IGNORECASE | re.MULTILINE):
        return "yara_rule"

    # Certificate fingerprints (SHA1 thumbprint)
    if re.match(r"^[a-fA-F0-9]{40}$", input_value) and ":" not in input_value:
        # Could be SHA1 hash or certificate thumbprint - context matters
        return "sha1"  # Will be handled as hash

    # MAC addresses
    if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", input_value):
        return "mac_address"

    # JA3 fingerprints
    if re.match(r"^[a-fA-F0-9]{32}$", input_value):
        # Could be MD5 or JA3 - treating as MD5 for now
        return "md5"

    # Domains (enhanced)
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", input_value):
        return "domain"

    # Subdomains or hostnames
    if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", input_value) and input_value.count('.') >= 1:
        return "hostname"

    # Process names
    if re.match(r"^[a-zA-Z0-9_\-]+\.exe$", input_value, re.IGNORECASE):
        return "process_name"

    # Port numbers
    if re.match(r"^\d{1,5}$", input_value) and 1 <= int(input_value) <= 65535:
        return "port"

    return "unknown"

def normalize_ioc(input_value: str, ioc_type: str) -> tuple:
    """
    Normalize IOC based on its type and return (normalized_value, final_type)
    """
    input_value = input_value.strip()
    
    # Handle URL variations
    if ioc_type == "url_no_protocol":
        return f"http://{input_value}", "url"
    elif ioc_type == "url":
        return input_value, "url"
    
    # Convert specific hash types to generic 'hash' for API compatibility
    if ioc_type in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "tlsh", "imphash", "ssdeep"]:
        return input_value.lower(), "hash"
    
    # Convert IPv4/IPv6 to generic 'ip'
    if ioc_type in ["ipv4", "ipv6"]:
        return input_value, "ip"
    
    # Extract domain from URL for domain-based analysis
    if ioc_type == "url":
        domain = extract_domain_from_url(input_value)
        return domain, "domain"
    
    # Handle hostname as domain
    if ioc_type == "hostname":
        return input_value, "domain"
    
    # For other types, return as-is with original type
    return input_value, ioc_type

def extract_domain_from_url(url: str) -> str:
    """Enhanced domain extraction with better error handling"""
    try:
        if not url.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        # Fallback regex extraction
        match = re.search(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9\-\.]+)', url)
        return match.group(1) if match else url

def resolve_domain(domain: str):
    """Enhanced domain resolution with better error handling"""
    import socket
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.herror, UnicodeError):
        return None

def retry_request(method, url, headers=None, params=None, json=None, retries=2, delay=2, timeout=10):
    """Enhanced retry logic with exponential backoff"""
    for attempt in range(retries + 1):
        try:
            if method.upper() == "GET":
                return requests.get(url, headers=headers, params=params, timeout=timeout)
            elif method.upper() == "POST":
                return requests.post(url, headers=headers, json=json, timeout=timeout)
        except requests.RequestException as e:
            if attempt < retries:
                wait_time = delay * (2 ** attempt)  # Exponential backoff
                time.sleep(wait_time)
            else:
                raise e

def get_ioc_description(ioc_type: str) -> str:
    """Get human-readable description of IOC type"""
    descriptions = {
        "threatfox_query": "ThreatFox Advanced Query",
        "email": "Email Address",
        "url": "URL/Web Address", 
        "ipv4": "IPv4 Address",
        "ipv6": "IPv6 Address",
        "cidr_ipv4": "IPv4 CIDR Block",
        "cidr_ipv6": "IPv6 CIDR Block",
        "md5": "MD5 Hash",
        "sha1": "SHA1 Hash",
        "sha224": "SHA224 Hash",
        "sha256": "SHA256 Hash", 
        "sha384": "SHA384 Hash",
        "sha512": "SHA512 Hash",
        "tlsh": "TLSH Hash",
        "imphash": "Import Hash",
        "ssdeep": "SSDeep Hash",
        "registry_key": "Registry Key",
        "file_path_windows": "Windows File Path",
        "file_path_unix": "Unix/Linux File Path", 
        "mutex": "Mutex Name",
        "user_agent": "User-Agent String",
        "bitcoin_address": "Bitcoin Address",
        "cve": "CVE Identifier",
        "asn": "Autonomous System Number",
        "yara_rule": "YARA Rule",
        "mac_address": "MAC Address",
        "domain": "Domain Name",
        "hostname": "Hostname",
        "process_name": "Process Name",
        "port": "Port Number",
        "ip": "IP Address",
        "hash": "File Hash",
        "unknown": "Unknown Type"
    }
    return descriptions.get(ioc_type, "Unknown Type")

def validate_ioc(input_value: str, ioc_type: str) -> tuple:
    """
    Validate IOC and return (is_valid, error_message)
    """
    input_value = input_value.strip()
    
    if not input_value:
        return False, "Empty input provided"
    
    if ioc_type == "unknown":
        return False, "Unrecognized IOC type. Please check your input format."
    
    # Additional validation for specific types
    if ioc_type in ["ipv4", "ipv6"]:
        try:
            ipaddress.ip_address(input_value)
            return True, None
        except ipaddress.AddressValueError:
            return False, f"Invalid {ioc_type.upper()} address format"
    
    if ioc_type == "domain":
        if len(input_value) > 253:
            return False, "Domain name too long (max 253 characters)"
        if '..' in input_value:
            return False, "Invalid domain format (consecutive dots)"
    
    if ioc_type.startswith("sha") or ioc_type in ["md5", "tlsh"]:
        if not re.match(r"^[a-fA-F0-9]+$", input_value):
            return False, f"Invalid {ioc_type.upper()} hash format (must be hexadecimal)"
    
    return True, None