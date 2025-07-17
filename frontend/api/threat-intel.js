// api/threat-intel.js
// Consolidated threat intelligence API endpoint

export default async function handler(req, res) {
    const { source, ...params } = req.query;
  
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    try {
      switch (source) {
        case 'abuseipdb':
          return await handleAbuseIPDB(req, res);
        case 'ipinfo':
          return await handleIPInfo(req, res);
        case 'malwarebazaar':
          return await handleMalwareBazaar(req, res);
        case 'otx':
          return await handleOTX(req, res);
        case 'shodan':
          return await handleShodan(req, res);
        case 'threatfox':
          return await handleThreatFox(req, res);
        case 'urlhaus':
          return await handleURLHaus(req, res);
        case 'urlscan':
          return await handleURLScan(req, res);
        case 'virustotal':
          return await handleVirusTotal(req, res);
        default:
          return res.status(400).json({ error: 'Invalid source specified. Use: abuseipdb, ipinfo, malwarebazaar, otx, shodan, threatfox, urlhaus, urlscan, or virustotal' });
      }
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }
  
  // AbuseIPDB Handler
  async function handleAbuseIPDB(req, res) {
    const { ip, originalDomain } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP parameter required' });
    }
  
    const result = await checkIP(ip, originalDomain);
    return res.status(200).json(result);
  }
  
  async function checkIP(ip, originalDomain = null) {
    const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
    
    if (!ABUSEIPDB_API_KEY) {
      return { error: "Missing AbuseIPDB API key." };
    }
  
    const url = "https://api.abuseipdb.com/api/v2/check";
    const params = new URLSearchParams({
      ipAddress: ip,
      maxAgeInDays: "90"
    });
    
    const headers = {
      "Key": ABUSEIPDB_API_KEY,
      "Accept": "application/json"
    };
  
    try {
      const response = await fetch(`${url}?${params}`, { 
        headers, 
        timeout: 10000 
      });
      
      if (response.ok) {
        const responseData = await response.json();
        const data = responseData.data;
        
        const result = {
          "IP Address": data.ipAddress,
          "Abuse Score": data.abuseConfidenceScore,
          "Country": data.countryCode,
          "ISP": data.isp || "N/A",
          "Domain": data.domain || "N/A",
          "Usage Type": data.usageType || "N/A",
          "Total Reports": data.totalReports,
          "Last Reported": data.lastReportedAt || "N/A"
        };
  
        if (originalDomain) {
          result["⚠️ Resolved Lookup"] = `IP shown was resolved from ${originalDomain}`;
        }
  
        return result;
      } else {
        const errorText = await response.text();
        return { 
          error: `AbuseIPDB HTTP ${response.status}`, 
          details: errorText 
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // IPInfo Handler
  async function handleIPInfo(req, res) {
    const { ip, originalDomain } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP parameter required' });
    }
  
    const result = await lookupIPInfo(ip, originalDomain);
    return res.status(200).json(result);
  }
  
  async function lookupIPInfo(ip, originalDomain = null) {
    const IPINFO_API_KEY = process.env.IPINFO_TOKEN;
    if (!IPINFO_API_KEY) {
      return { error: "Missing IPinfo API key." };
    }
  
    const url = `https://ipinfo.io/${ip}/json`;
    const headers = {
      "Authorization": `Bearer ${IPINFO_API_KEY}`
    };
  
    try {
      const response = await fetch(url, { headers, timeout: 10000 });
      
      if (response.ok) {
        const data = await response.json();
        const result = {
          "IP": data.ip,
          "Hostname": data.hostname,
          "City": data.city,
          "Region": data.region,
          "Country": data.country,
          "Organization": data.org,
          "ASN": data.asn?.asn || "N/A"
        };
  
        if (originalDomain) {
          result["⚠️ Resolved Lookup"] = `IP shown was resolved from ${originalDomain}`;
        }
  
        return result;
      } else {
        const errorText = await response.text();
        return { error: `IPinfo HTTP ${response.status}`, details: errorText };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // MalwareBazaar Handler
  async function handleMalwareBazaar(req, res) {
    const { ioc } = req.body;
    
    if (!ioc) {
      return res.status(400).json({ error: 'IOC parameter required' });
    }
  
    const result = await lookupMalwareBazaar(ioc);
    return res.status(200).json(result);
  }
  
  async function lookupMalwareBazaar(ioc) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    if (!ABUSECH_API_KEY) {
      return { error: "Missing Abuse.ch API key for MalwareBazaar." };
    }
  
    const trimmedIOC = ioc.trim();
  
    // Check if it's a search query or hash
    if (trimmedIOC.includes(":") && !trimmedIOC.match(/^[a-fA-F0-9]{32,64}$/)) {
      return await advancedSearchMB(trimmedIOC);
    }
  
    // Hash lookup
    const payload = { query: "get_info", hash: trimmedIOC };
  
    try {
      const response = await fetch("https://mb-api.abuse.ch/api/v1/", {
        method: 'POST',
        headers: {
          "User-Agent": "ai-soc-agent/1.0",
          "Auth-Key": ABUSECH_API_KEY
        },
        body: new URLSearchParams(payload),
        timeout: 10000
      });
  
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
  
      const data = await response.json();
      
      if (data.query_status === "ok" && data.data) {
        const entry = data.data[0];
        return {
          found: true,
          "SHA256": entry.sha256_hash,
          "File Name": entry.file_name,
          "File Type": entry.file_type_mime,
          "File Size": entry.file_size,
          "Signature": entry.signature,
          "Tags": entry.tags,
          "Vendor Detections": entry.vendor_intel || {},
          "Delivery Method": entry.delivery_method,
          "First Seen": entry.first_seen,
          "Last Seen": entry.last_seen,
          "Comment": entry.comment,
          "Reporter": entry.reporter,
          "Intelligence": entry.intelligence || {}
        };
      } else if (data.query_status === "hash_not_found") {
        return { message: "Hash not found in MalwareBazaar." };
      } else if (data.query_status === "no_results") {
        return { message: "No MalwareBazaar results found." };
      } else if (data.query_status === "missing_query") {
        return { error: "Invalid query format for MalwareBazaar API." };
      } else {
        return {
          status: data.query_status,
          reason: data.reason || "No reason provided."
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async function advancedSearchMB(term) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    const payload = {
      query: "search",
      search_term: term
    };
    
    try {
      const response = await fetch("https://mb-api.abuse.ch/api/v1/", {
        method: 'POST',
        headers: {
          "User-Agent": "ai-soc-agent/1.0",
          "Auth-Key": ABUSECH_API_KEY
        },
        body: new URLSearchParams(payload),
        timeout: 10000
      });
  
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
  
      const data = await response.json();
      
      if (data.query_status === "ok" && data.data) {
        return {
          found: true,
          results: data.data.slice(0, 5).map(entry => ({
            "SHA256": entry.sha256_hash,
            "File Name": entry.file_name,
            "File Type": entry.file_type_mime,
            "Signature": entry.signature,
            "Tags": entry.tags,
            "First Seen": entry.first_seen,
            "Reporter": entry.reporter,
            "File Size": entry.file_size
          }))
        };
      } else if (data.query_status === "no_results") {
        return { message: "No MalwareBazaar search results found." };
      } else {
        return {
          status: data.query_status,
          reason: data.reason || "No data matched."
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // OTX Handler
  async function handleOTX(req, res) {
    const { ioc, iocType } = req.body;
    
    if (!ioc || !iocType) {
      return res.status(400).json({ error: 'IOC and iocType parameters required' });
    }
  
    const result = await lookupOTX(ioc, iocType);
    return res.status(200).json(result);
  }
  
  function sanitizeIOC(ioc, iocType) {
    if (iocType === "url") {
      try {
        const url = new URL(ioc.startsWith('http') ? ioc : `http://${ioc}`);
        return url.hostname || ioc;
      } catch {
        return ioc;
      }
    }
    return ioc;
  }
  
  async function lookupOTX(ioc, iocType) {
    const OTX_API_KEY = process.env.OTX_API_KEY;
    if (!OTX_API_KEY) {
      return { error: "Missing OTX API key." };
    }
  
    const sanitizedIOC = sanitizeIOC(ioc, iocType);
    const baseUrl = "https://otx.alienvault.com/api/v1/indicators";
  
    let url;
    if (iocType === "ip") {
      url = `${baseUrl}/IPv4/${sanitizedIOC}/general`;
    } else if (iocType === "domain" || iocType === "url") {
      url = `${baseUrl}/domain/${sanitizedIOC}/general`;
    } else if (iocType === "hash") {
      url = `${baseUrl}/file/${sanitizedIOC}/general`;
    } else {
      return { error: `Unsupported IOC type for OTX: ${iocType}` };
    }
  
    const headers = {
      "X-OTX-API-KEY": OTX_API_KEY,
      "User-Agent": "ai-soc-agent"
    };
  
    try {
      const response = await fetch(url, { headers, timeout: 10000 });
      if (response.ok) {
        return await response.json();
      } else {
        const errorText = await response.text();
        return {
          error: `OTX HTTP ${response.status}`,
          details: errorText
        };
      }
    } catch (error) {
      return { error: `Request failed: ${error.message}` };
    }
  }
  
  // Shodan Handler
  async function handleShodan(req, res) {
    const { ip } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP parameter required' });
    }
  
    const result = await lookupShodan(ip);
    return res.status(200).json(result);
  }
  
  async function lookupShodan(ip) {
    const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
    
    if (!SHODAN_API_KEY) {
      return { error: "Missing Shodan API key." };
    }
  
    try {
      const url = `https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`;
      const response = await fetch(url, { timeout: 10000 });
      
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `Shodan API error: ${response.status} - ${errorText}` };
      }
      
      const host = await response.json();
      
      const result = {
        "ip": host.ip_str,
        "organization": host.org,
        "os": host.os,
        "last_update": host.last_update,
        "open_ports": host.ports,
        "hostnames": host.hostnames,
        "country": host.country_name,
        "isp": host.isp,
        "tags": host.tags,
        "vulns": host.vulns ? Array.from(host.vulns) : [],
      };
      
      return result;
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // ThreatFox Handler
  async function handleThreatFox(req, res) {
    const { ioc } = req.body;
    
    if (!ioc) {
      return res.status(400).json({ error: 'IOC parameter required' });
    }
  
    const result = await lookupThreatFox(ioc);
    return res.status(200).json(result);
  }
  
  async function lookupThreatFox(ioc) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    if (!ABUSECH_API_KEY) {
      return { error: "Missing Abuse.ch API key." };
    }
  
    const url = "https://threatfox-api.abuse.ch/api/v1/";
    const headers = {
      "User-Agent": "ai-soc-agent/1.0",
      "Content-Type": "application/json",
      "Accept": "application/json",
      "Auth-Key": ABUSECH_API_KEY
    };
  
    const payload = {
      query: ioc.startsWith(("ioc:", "malware:", "tag:", "uuid:", "threat_type:")) 
        ? "search_advanced" 
        : "search_ioc",
      search_term: ioc
    };
  
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeout: 10000
      });
      
      if (response.ok) {
        const data = await response.json();
        
        if (data.query_status === "ok") {
          const results = data.data || [];
          return results.length > 0 ? results : { message: "No ThreatFox results found." };
        } else if (data.query_status === "no_result") {
          return { message: "No ThreatFox results found." };
        } else {
          return {
            status: data.query_status,
            reason: data.reason || "No reason provided."
          };
        }
      } else if (response.status === 401) {
        return { error: "HTTP 401 Unauthorized. Check API key and headers." };
      } else {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // URLHaus Handler
  async function handleURLHaus(req, res) {
    const { ioc } = req.body;
    
    if (!ioc) {
      return res.status(400).json({ error: 'IOC parameter required' });
    }
  
    const result = await lookupURLHaus(ioc);
    return res.status(200).json(result);
  }
  
  async function lookupURLHaus(ioc) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    if (!ABUSECH_API_KEY) {
      return { error: "Missing Abuse.ch API key for URLHaus." };
    }
  
    const trimmedIOC = ioc.trim();
  
    // Check if it's a search query or hash
    if (trimmedIOC.includes(":") && !trimmedIOC.match(/^[a-fA-F0-9]{64}$/)) {
      return await searchURLHaus(trimmedIOC);
    }
  
    // Hash lookup
    let payload;
    if (trimmedIOC.match(/^[a-fA-F0-9]{32}$/)) {
      payload = { md5_hash: trimmedIOC };
    } else if (trimmedIOC.match(/^[a-fA-F0-9]{64}$/)) {
      payload = { sha256_hash: trimmedIOC };
    } else {
      return { error: "Invalid hash format for URLhaus lookup" };
    }
  
    try {
      const response = await fetch("https://urlhaus-api.abuse.ch/v1/payload/", {
        method: 'POST',
        headers: {
          "User-Agent": "ai-soc-agent/1.0",
          "Auth-Key": ABUSECH_API_KEY
        },
        body: new URLSearchParams(payload),
        timeout: 10000
      });
  
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
  
      const data = await response.json();
      
      if (data.query_status === "ok") {
        return {
          found: true,
          "SHA256": data.sha256_hash,
          "MD5": data.md5_hash,
          "File Size": data.file_size,
          "File Type": data.file_type,
          "First Seen": data.firstseen,
          "Last Seen": data.lastseen,
          "URL Count": (data.urls || []).length,
          "URLs": (data.urls || []).slice(0, 3).map(url => url.url)
        };
      } else if (data.query_status === "no_results") {
        return { message: "No URLhaus results found." };
      } else {
        return {
          status: data.query_status,
          reason: data.reason || "No reason provided."
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async function searchURLHaus(term) {
    const ABUSECH_API_KEY = process.env.ABUSECH_API_KEY;
    const payload = {
      query: "search",
      search_term: term
    };
    
    try {
      const response = await fetch("https://urlhaus-api.abuse.ch/v1/", {
        method: 'POST',
        headers: {
          "User-Agent": "ai-soc-agent/1.0",
          "Auth-Key": ABUSECH_API_KEY
        },
        body: new URLSearchParams(payload),
        timeout: 10000
      });
  
      if (!response.ok) {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}`, details: errorText };
      }
  
      const data = await response.json();
      
      if (data.query_status === "ok" && data.urls) {
        return {
          found: true,
          results: data.urls.slice(0, 5).map(item => ({
            "URL": item.url,
            "Host": item.host,
            "Threat": item.threat,
            "Tags": item.tags,
            "Date Added": item.date_added,
            "Reporter": item.reporter,
            "URL Status": item.url_status,
          }))
        };
      } else if (data.query_status === "no_results") {
        return { message: "No URLhaus search results found." };
      } else {
        return {
          status: data.query_status,
          reason: data.reason || "No data matched."
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // URLScan Handler
  async function handleURLScan(req, res) {
    const { ioc } = req.body;
    
    if (!ioc) {
      return res.status(400).json({ error: 'IOC parameter required' });
    }
  
    const result = await lookupURLScan(ioc);
    return res.status(200).json(result);
  }
  
  async function lookupURLScan(ioc) {
    const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
    if (!URLSCAN_API_KEY) {
      return { error: "Missing URLScan API key." };
    }
  
    let url = ioc;
    if (!url.startsWith("http")) {
      url = "http://" + url;
    }
  
    return await activeScan(url);
  }
  
  async function activeScan(url) {
    const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
    const headers = {
      "API-Key": URLSCAN_API_KEY,
      "Content-Type": "application/json",
      "Accept": "application/json"
    };
  
    const payload = {
      url: url,
      visibility: "public"
    };
  
    try {
      const postResponse = await fetch("https://urlscan.io/api/v1/scan/", {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeout: 10000
      });
  
      if (!postResponse.ok) {
        const errorText = await postResponse.text();
        return { error: `URLScan Active HTTP ${postResponse.status}`, details: errorText };
      }
  
      const postData = await postResponse.json();
      const scanId = postData.uuid;
      const result = await waitForResult(scanId);
  
      if (!result) {
        return { error: "URLScan result not ready after timeout." };
      }
  
      const page = result.page || {};
      const lists = result.lists || {};
      const task = result.task || {};
      const verdicts = result.verdicts?.overall || {};
  
      return {
        method: "active",
        summary: {
          "Scan URL": task.url,
          "Scan Time": task.time,
          "Visibility": task.visibility,
          "Verdict Score": verdicts.score,
          "Verdict Tags": (verdicts.tags || []).join(", "),
          "Status": page.status,
          "MIME Type": page.mimeType,
          "Server": page.server,
        },
        domain_info: {
          "Domain": page.domain,
          "IP": page.ip,
          "ASN": page.asn,
          "ASN Name": page.asnname,
          "Country": page.country,
          "TLS Issuer": page.tlsIssuer,
        },
        http: {
          "Redirects": (lists.redirects || []).map(r => r.response?.url).filter(Boolean),
          "Indicators": lists.verdicts || {},
          "Behaviors": lists.behavior || {},
        },
        screenshot: result.screenshot,
        reportURL: task.reportURL,
        raw: result
      };
  
    } catch (error) {
      return { error: error.message };
    }
  }
  
  async function waitForResult(scanId, timeout = 30000, interval = 5000) {
    const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
    const headers = {
      "API-Key": URLSCAN_API_KEY,
      "Content-Type": "application/json",
      "Accept": "application/json"
    };
  
    const resultUrl = `https://urlscan.io/api/v1/result/${scanId}/`;
    const maxAttempts = Math.floor(timeout / interval);
    
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const response = await fetch(resultUrl, { headers, timeout: 10000 });
        if (response.ok) {
          return await response.json();
        }
      } catch (error) {
        // Continue trying
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    return null;
  }
  
  // VirusTotal Handler
  async function handleVirusTotal(req, res) {
    const { ioc } = req.body;
    
    if (!ioc) {
      return res.status(400).json({ error: 'IOC parameter required' });
    }
  
    const result = await checkVirusTotal(ioc);
    return res.status(200).json(result);
  }
  
  async function checkVirusTotal(ioc) {
    const VT_API_KEY = process.env.VT_API_KEY;
    
    if (!VT_API_KEY) {
      return { error: "Missing VirusTotal API key." };
    }
  
    const headers = {
      "x-apikey": VT_API_KEY,
      "Accept": "application/json"
    };
  
    try {
      // 1. Search
      const searchUrl = `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(ioc)}`;
      const searchResponse = await fetch(searchUrl, { 
        headers, 
        timeout: 10000 
      });
      
      if (!searchResponse.ok) {
        const errorText = await searchResponse.text();
        return { 
          error: `VT Search HTTP ${searchResponse.status}`, 
          details: errorText 
        };
      }
  
      const searchData = await searchResponse.json();
      
      if (!searchData.data || searchData.data.length === 0) {
        return { message: "No data found in VirusTotal search." };
      }
  
      const item = searchData.data[0];
      const itemId = item.id;
      const itemType = item.type;
  
      if (!itemId || !itemType) {
        return { message: "Unable to determine ID/type from VT search result." };
      }
  
      // 2. Main detail query
      const baseDetailUrl = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}`;
      const detailResponse = await fetch(baseDetailUrl, { 
        headers, 
        timeout: 10000 
      });
      
      if (!detailResponse.ok) {
        const errorText = await detailResponse.text();
        return { 
          error: `VT Detail HTTP ${detailResponse.status}`, 
          details: errorText 
        };
      }
  
      const details = await detailResponse.json();
  
      // 3. Enrich with related data (where applicable)
      const relatedData = {};
  
      const fetchRelation = async (relationship) => {
        try {
          const url = `https://www.virustotal.com/api/v3/${itemType}s/${itemId}/relationships/${relationship}`;
          const response = await fetch(url, { 
            headers, 
            timeout: 10000 
          });
          
          if (response.ok) {
            const data = await response.json();
            return data.data || [];
          }
          return [];
        } catch (error) {
          return [];
        }
      };
  
      if (itemType === "domain") {
        relatedData.resolutions = await fetchRelation("resolutions");
        relatedData.communicating_files = await fetchRelation("communicating_files");
        relatedData.downloaded_files = await fetchRelation("downloaded_files");
      } else if (itemType === "ip_address") {
        relatedData.resolutions = await fetchRelation("resolutions");
        relatedData.contacted_domains = await fetchRelation("contacted_domains");
      } else if (itemType === "url") {
        relatedData.downloaded_files = await fetchRelation("downloaded_files");
      } else if (itemType === "file") {
        relatedData.contacted_domains = await fetchRelation("contacted_domains");
        relatedData.contacted_ips = await fetchRelation("contacted_ips");
      }
  
      return {
        details: details,
        related: relatedData
      };
  
    } catch (error) {
      return { error: error.message };
    }
  }
  
  // Export individual functions for use in other endpoints
  export { 
    checkIP, 
    lookupIPInfo, 
    lookupMalwareBazaar, 
    lookupOTX, 
    lookupShodan, 
    lookupThreatFox, 
    lookupURLHaus, 
    lookupURLScan, 
    checkVirusTotal 
  };