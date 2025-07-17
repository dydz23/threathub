// api/analyze.js
// Main analysis endpoint - converted from main.py

import { detectInputType, normalizeIoc, validateIoc, getIocDescription, extractDomainFromUrl, resolveDomain } from '../utils/iocDetection.js';
import { formatVirusTotal, formatAbuseIPDB, formatShodan, formatOTX, formatThreatFox, formatURLHaus, formatMalwareBazaar, formatIPInfo, formatURLScan } from '../utils/formatters.js';
import { SOCAnalystLLM } from '../utils/claude.js';
import { 
  checkVirusTotal, 
  checkIP, 
  lookupShodan, 
  lookupOTX, 
  lookupThreatFox, 
  lookupURLScan, 
  lookupURLHaus, 
  lookupMalwareBazaar, 
  lookupIPInfo 
} from './threat-intel.js';

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    const { input } = req.body;
    const inputValue = input?.trim();

    if (!inputValue) {
      return res.status(400).json({
        detail: "Must provide input value for analysis."
      });
    }

    // Detect IOC type
    const detectedType = detectInputType(inputValue);
    
    // Validate IOC
    const [isValid, errorMessage] = validateIoc(inputValue, detectedType);
    if (!isValid) {
      return res.status(400).json({
        detail: errorMessage,
        detected_type: detectedType,
        type_description: getIocDescription(detectedType)
      });
    }
    
    // Normalize IOC for API processing
    const [normalizedValue, finalType] = normalizeIoc(inputValue, detectedType);

    // Handle special case: ThreatFox query
    if (finalType === "threatfox_query") {
      const tfRaw = await lookupThreatFox(normalizedValue);
      const formattedTf = formatThreatFox(tfRaw);
      
      const structuredData = {
        input: inputValue,
        normalized_input: normalizedValue,
        type: finalType,
        type_description: getIocDescription(finalType),
        threatfox: formattedTf,
        virustotal: {},
        abuseipdb: {},
        shodan: {},
        otx: {},
        urlhaus: {},
        malwarebazaar: {},
        ipinfo: {},
        urlscan: {}
      };
      
      const socAnalyst = new SOCAnalystLLM();
      const socAnalysis = await socAnalyst.generateSOCAnalysis(structuredData);
      
      return res.status(200).json({
        input: inputValue,
        normalized_input: normalizedValue,
        type: finalType,
        type_description: getIocDescription(finalType),
        threatfox: formattedTf,
        soc_analysis: socAnalysis,
        summary: socAnalysis.llm_analysis
      });
    }

    // Handle unsupported IOC types
    const unsupportedTypes = [
      "email", "cidr_ipv4", "cidr_ipv6", "registry_key", "file_path_windows", 
      "file_path_unix", "mutex", "user_agent", "bitcoin_address", "cve", 
      "asn", "yara_rule", "mac_address", "process_name", "port"
    ];
    
    if (unsupportedTypes.includes(finalType)) {
      return res.status(400).json({
        detail: `IOC type '${getIocDescription(finalType)}' is not yet supported for threat intelligence analysis.`,
        detected_type: finalType,
        type_description: getIocDescription(finalType),
        supported_types: ["ip", "domain", "url", "hash", "threatfox_query"]
      });
    }

    // Convert URL to domain for analysis
    let processedValue = normalizedValue;
    let processedType = finalType;
    
    if (finalType === "url") {
      processedValue = extractDomainFromUrl(normalizedValue);
      processedType = "domain";
    }

    // Initialize results structure
    const results = {
      input: inputValue,
      normalized_input: normalizedValue,
      type: processedType,
      type_description: getIocDescription(processedType),
      virustotal: {},
      abuseipdb: {},
      shodan: {},
      otx: {},
      threatfox: {},
      urlhaus: {},
      malwarebazaar: {},
      ipinfo: {},
      urlscan: {},
    };

    // ---- URLScan Active Scan ----
    if (finalType === "url" || processedType === "domain") {
      try {
        const urlscanRaw = await lookupURLScan(finalType === "url" ? normalizedValue : processedValue);
        if (urlscanRaw?.method === "active") {
          results.urlscan = {
            method: "active",
            summary: urlscanRaw.summary || {},
            domain_info: urlscanRaw.domain_info || {},
            http: urlscanRaw.http || {},
            screenshot: urlscanRaw.screenshot,
            reportURL: urlscanRaw.reportURL
          };
        } else {
          results.urlscan = { message: "URLScan active scan failed." };
        }
      } catch (error) {
        results.urlscan = { error: error.message };
      }
    }

    // ---- Main Threat Intelligence Lookups ----
    let resolvedIp = null;
    
    if (processedType === "domain") {
      resolvedIp = await resolveDomain(processedValue);
      if (!resolvedIp) {
        return res.status(400).json({
          detail: `Failed to resolve domain: ${processedValue}`
        });
      }
      
      // Execute all relevant lookups for domain
      const [abuseResult, ipinfoResult, shodanResult, otxResult, threatfoxResult, vtResult] = await Promise.allSettled([
        checkIP(resolvedIp, processedValue),
        lookupIPInfo(resolvedIp, processedValue),
        lookupShodan(resolvedIp),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        checkVirusTotal(processedValue)
      ]);

      results.abuseipdb = formatAbuseIPDB(abuseResult.status === 'fulfilled' ? abuseResult.value : { error: abuseResult.reason?.message });
      results.ipinfo = formatIPInfo(ipinfoResult.status === 'fulfilled' ? ipinfoResult.value : { error: ipinfoResult.reason?.message });
      results.shodan = formatShodan(shodanResult.status === 'fulfilled' ? shodanResult.value : { error: shodanResult.reason?.message });
      results.otx = formatOTX(otxResult.status === 'fulfilled' ? otxResult.value : { error: otxResult.reason?.message });
      results.threatfox = formatThreatFox(threatfoxResult.status === 'fulfilled' ? threatfoxResult.value : { error: threatfoxResult.reason?.message });
      results.virustotal = formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message });

    } else if (processedType === "ip") {
      // Execute all relevant lookups for IP
      const [abuseResult, shodanResult, ipinfoResult, otxResult, threatfoxResult, vtResult] = await Promise.allSettled([
        checkIP(processedValue),
        lookupShodan(processedValue),
        lookupIPInfo(processedValue),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        checkVirusTotal(processedValue)
      ]);

      results.abuseipdb = formatAbuseIPDB(abuseResult.status === 'fulfilled' ? abuseResult.value : { error: abuseResult.reason?.message });
      results.shodan = formatShodan(shodanResult.status === 'fulfilled' ? shodanResult.value : { error: shodanResult.reason?.message });
      results.ipinfo = formatIPInfo(ipinfoResult.status === 'fulfilled' ? ipinfoResult.value : { error: ipinfoResult.reason?.message });
      results.otx = formatOTX(otxResult.status === 'fulfilled' ? otxResult.value : { error: otxResult.reason?.message });
      results.threatfox = formatThreatFox(threatfoxResult.status === 'fulfilled' ? threatfoxResult.value : { error: threatfoxResult.reason?.message });
      results.virustotal = formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message });

    } else if (processedType === "hash") {
      // Execute all relevant lookups for hash
      const [vtResult, otxResult, threatfoxResult, urlhausResult, mbResult] = await Promise.allSettled([
        checkVirusTotal(processedValue),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        lookupURLHaus(processedValue),
        lookupMalwareBazaar(processedValue)
      ]);

      results.virustotal = formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message });
      results.otx = formatOTX(otxResult.status === 'fulfilled' ? otxResult.value : { error: otxResult.reason?.message });
      results.threatfox = formatThreatFox(threatfoxResult.status === 'fulfilled' ? threatfoxResult.value : { error: threatfoxResult.reason?.message });
      results.urlhaus = formatURLHaus(urlhausResult.status === 'fulfilled' ? urlhausResult.value : { error: urlhausResult.reason?.message });
      results.malwarebazaar = formatMalwareBazaar(mbResult.status === 'fulfilled' ? mbResult.value : { error: mbResult.reason?.message });

    } else {
      return res.status(400).json({
        detail: `Unsupported IOC type for analysis: ${processedType}`
      });
    }

    // ---- Raw Data Collection ----
    const rawPromises = [];
    const rawSources = [];

    // Collect raw data based on IOC type
    if (processedType === "domain" && resolvedIp) {
      rawPromises.push(
        checkVirusTotal(processedValue),
        checkIP(resolvedIp),
        lookupShodan(resolvedIp),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        lookupURLHaus(processedValue),
        lookupMalwareBazaar(processedValue),
        lookupIPInfo(resolvedIp),
        lookupURLScan(processedValue)
      );
      rawSources.push('virustotal', 'abuseipdb', 'shodan', 'otx', 'threatfox', 'urlhaus', 'malwarebazaar', 'ipinfo', 'urlscan');
    } else if (processedType === "ip") {
      rawPromises.push(
        checkVirusTotal(processedValue),
        checkIP(processedValue),
        lookupShodan(processedValue),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        lookupURLHaus(processedValue),
        lookupMalwareBazaar(processedValue),
        lookupIPInfo(processedValue),
        lookupURLScan(processedValue)
      );
      rawSources.push('virustotal', 'abuseipdb', 'shodan', 'otx', 'threatfox', 'urlhaus', 'malwarebazaar', 'ipinfo', 'urlscan');
    } else if (processedType === "hash") {
      rawPromises.push(
        checkVirusTotal(processedValue),
        lookupOTX(processedValue, processedType),
        lookupThreatFox(processedValue),
        lookupURLHaus(processedValue),
        lookupMalwareBazaar(processedValue)
      );
      rawSources.push('virustotal', 'otx', 'threatfox', 'urlhaus', 'malwarebazaar');
    }

    const rawResults = await Promise.allSettled(rawPromises);
    results.raw = {};
    rawSources.forEach((source, index) => {
      results.raw[source] = rawResults[index]?.status === 'fulfilled' 
        ? rawResults[index].value 
        : { error: rawResults[index]?.reason?.message || 'Unknown error' };
    });

    // ---- Enhanced SOC Analysis ----
    const socAnalyst = new SOCAnalystLLM();
    const socAnalysis = await socAnalyst.generateSOCAnalysis(results);
    
    // Add SOC analysis to results
    results.soc_analysis = socAnalysis;
    
    // Backwards compatibility - keep the summary field
    results.summary = socAnalysis.llm_analysis;
    
    // Add metadata for better tracking
    results.metadata = {
      analyst_version: "2.0",
      confidence_level: socAnalysis.confidence_level,
      risk_level: socAnalysis.risk_assessment.level,
      risk_score: socAnalysis.risk_assessment.score,
      recommended_actions: socAnalysis.recommended_actions,
      analysis_timestamp: socAnalysis.timestamp
    };

    return res.status(200).json(results);

  } catch (error) {
    console.error('Analysis error:', error);
    return res.status(500).json({
      detail: `Analysis failed: ${error.message}`,
      error_type: error.constructor.name
    });
  }
}