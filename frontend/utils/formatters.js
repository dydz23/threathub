// utils/formatters.js
// Converted from api/formatters.py

function formatTimestamp(ts) {
    if (!ts) return null;
    try {
      return new Date(parseInt(ts) * 1000).toISOString().replace('T', ' ').substring(0, 19);
    } catch {
      return ts; // fallback if already formatted
    }
  }
  
  export function formatVirusTotal(data) {
    if (!data || typeof data !== 'object') {
      return { message: "Invalid VT data format." };
    }
    if (data.error) return data;
    if (data.message) return { message: data.message };
  
    let attributes, vtId;
    if (data.details) {
      attributes = data.details?.data?.attributes || {};
      vtId = data.details?.data?.id;
    } else {
      attributes = data.data?.attributes || {};
      vtId = data.data?.id;
    }
  
    const result = {
      "ID": vtId,
      "Reputation": attributes.reputation,
      "Type": attributes.type_description,
      "Meaningful Name": attributes.meaningful_name,
    };
  
    // Analysis statistics
    const stats = attributes.last_analysis_stats || {};
    if (Object.keys(stats).length > 0) {
      const total = (stats.malicious || 0) + (stats.harmless || 0) + (stats.undetected || 0) + (stats.suspicious || 0);
      result["Detection Ratio"] = `${stats.malicious || 0}/${total}`;
      result["Malicious Detections"] = stats.malicious || 0;
      result["Suspicious Detections"] = stats.suspicious || 0;
      result["Harmless Detections"] = stats.harmless || 0;
      result["Undetected"] = stats.undetected || 0;
      result["Timeout"] = stats.timeout || 0;
    }
  
    // Categories
    if (attributes.categories) {
      result["Categories"] = attributes.categories;
    }
  
    // Timestamps
    if (attributes.first_submission_date) {
      result["First Submission"] = formatTimestamp(attributes.first_submission_date);
    }
    if (attributes.last_analysis_date) {
      result["Last Analysis"] = formatTimestamp(attributes.last_analysis_date);
    }
    if (attributes.last_modification_date) {
      result["Last Modified"] = formatTimestamp(attributes.last_modification_date);
    }
  
    // Network information
    if (attributes.network) result["Network"] = attributes.network;
    if (attributes.country) result["Country"] = attributes.country;
    if (attributes.asn) result["ASN"] = attributes.asn;
    if (attributes.as_owner) result["AS Owner"] = attributes.as_owner;
  
    // File information
    if (attributes.size) result["File Size"] = `${attributes.size.toLocaleString()} bytes`;
    if (attributes.md5) result["MD5"] = attributes.md5;
    if (attributes.sha1) result["SHA1"] = attributes.sha1;
    if (attributes.sha256) result["SHA256"] = attributes.sha256;
    if (attributes.magic) result["File Magic"] = attributes.magic;
  
    // Signature info
    if (attributes.signature_info) {
      const sigInfo = attributes.signature_info;
      if (typeof sigInfo === 'object') {
        result["Signature Subject"] = sigInfo.subject || "N/A";
        result["Signature Issuer"] = sigInfo.issuer || "N/A";
        result["Signature Valid"] = sigInfo.verified || "Unknown";
      }
    }
  
    // Known names
    const names = attributes.names || [];
    if (names.length > 0) {
      result["Known Names"] = names.slice(0, 5);
    }
  
    // Sandbox verdicts
    const sandboxVerdicts = attributes.sandbox_verdicts || {};
    if (Object.keys(sandboxVerdicts).length > 0) {
      const sandboxResults = [];
      for (const [engine, verdict] of Object.entries(sandboxVerdicts)) {
        if (typeof verdict === 'object') {
          sandboxResults.push(`${engine}: ${verdict.category || 'N/A'}`);
        }
      }
      if (sandboxResults.length > 0) {
        result["Sandbox Verdicts"] = sandboxResults.slice(0, 3);
      }
    }
  
    // Related data
    const related = data.related || {};
    const extractIds = (entries, limit = 5) => {
      return entries.slice(0, limit).map(e => typeof e === 'object' ? e.id : e).filter(Boolean);
    };
  
    if (related.resolutions?.length > 0) {
      result["Resolved IPs"] = extractIds(related.resolutions);
    }
    if (related.communicating_files?.length > 0) {
      result["Communicating Files"] = extractIds(related.communicating_files);
    }
    if (related.downloaded_files?.length > 0) {
      result["Downloaded Files"] = extractIds(related.downloaded_files);
    }
    if (related.contacted_domains?.length > 0) {
      result["Contacted Domains"] = extractIds(related.contacted_domains);
    }
    if (related.contacted_ips?.length > 0) {
      result["Contacted IPs"] = extractIds(related.contacted_ips);
    }
  
    return result;
  }
  
  export function formatAbuseIPDB(data) {
    if (!data || typeof data !== 'object') return data;
    if (data.error) return data;
    
    const result = {};
    
    if (data["IP Address"]) result["IP Address"] = data["IP Address"];
    if (data["Abuse Score"] !== undefined) {
      result["Abuse Confidence"] = `${data["Abuse Score"]}%`;
      
      const score = data["Abuse Score"];
      if (score >= 75) result["Risk Level"] = "High Risk";
      else if (score >= 25) result["Risk Level"] = "Medium Risk";
      else result["Risk Level"] = "Low Risk";
    }
    
    if (data["Country"]) result["Country Code"] = data["Country"];
    if (data["ISP"]) result["ISP"] = data["ISP"];
    if (data["Domain"]) result["Domain"] = data["Domain"];
    if (data["Usage Type"]) result["Usage Type"] = data["Usage Type"];
    if (data["Total Reports"]) result["Total Reports"] = data["Total Reports"];
    if (data["Last Reported"]) result["Last Reported"] = data["Last Reported"];
    if (data["⚠️ Resolved Lookup"]) result["Resolution Note"] = data["⚠️ Resolved Lookup"];
    
    return result;
  }
  
  export function formatShodan(data) {
    if (!data || typeof data !== 'object') return data;
    if (data.error) return data;
    
    const result = {};
    
    if (data.ip) result["IP Address"] = data.ip;
    if (data.organization) result["Organization"] = data.organization;
    if (data.isp) result["ISP"] = data.isp;
    if (data.os) result["Operating System"] = data.os;
    if (data.country) result["Country"] = data.country;
    if (data.city) result["City"] = data.city;
    if (data.region_code) result["Region"] = data.region_code;
    
    if (data.open_ports?.length > 0) {
      result["Open Ports"] = data.open_ports;
      result["Total Open Ports"] = data.open_ports.length;
    }
    if (data.hostnames?.length > 0) {
      result["Hostnames"] = data.hostnames;
    }
    if (data.vulns?.length > 0) {
      result["Vulnerabilities"] = data.vulns;
      result["Vulnerability Count"] = data.vulns.length;
    }
    if (data.tags?.length > 0) {
      result["Tags"] = data.tags;
    }
    if (data.last_update) {
      result["Last Updated"] = data.last_update;
    }
    
    return result;
  }
  
  export function formatOTX(data) {
    if (!data || typeof data !== 'object') return data;
    if (data.error) return data;
    
    const result = {};
    
    if (data.indicator) result["Indicator"] = data.indicator;
    if (data.type) result["Type"] = data.type;
    if (data.type_title) result["Type Description"] = data.type_title;
    
    const pulseInfo = data.pulse_info || {};
    if (pulseInfo.pulses?.length > 0) {
      const pulses = pulseInfo.pulses;
      result["Pulse Count"] = pulses.length;
      
      const pulseNames = [];
      const pulseTags = new Set();
      const malwareFamilies = new Set();
      
      for (const pulse of pulses.slice(0, 5)) {
        if (pulse.name) pulseNames.push(pulse.name);
        if (pulse.tags) pulse.tags.forEach(tag => pulseTags.add(tag));
        if (pulse.malware_families) {
          pulse.malware_families.forEach(family => {
            if (typeof family === 'object' && family.display_name) {
              malwareFamilies.add(family.display_name);
            }
          });
        }
      }
      
      if (pulseNames.length > 0) result["Related Pulses"] = pulseNames;
      if (pulseTags.size > 0) result["Associated Tags"] = Array.from(pulseTags).slice(0, 10);
      if (malwareFamilies.size > 0) result["Malware Families"] = Array.from(malwareFamilies);
    }
    
    const general = data.general || {};
    if (general.sections) result["Available Sections"] = general.sections;
    if (general.whois) result["Whois Available"] = "Yes";
    if (general.reputation) result["Reputation"] = general.reputation;
    
    return result;
  }
  
  export function formatThreatFox(data) {
    if (!data) return { message: "No ThreatFox data returned." };
  
    if (typeof data === 'object' && !Array.isArray(data)) {
      if (data.error) return data;
      if (data.status || data.message) {
        return {
          "Status": data.status,
          "Message": data.message,
          "Reason": data.reason || "No reason provided"
        };
      }
    }
  
    if (Array.isArray(data) && data.length > 0) {
      return data.map(entry => {
        const formatted = {
          "IOC ID": entry.id,
          "IOC Value": entry.ioc,
          "IOC Type": entry.ioc_type,
          "Threat Type": entry.threat_type,
          "Malware Family": entry.malware,
          "Malware Alias": entry.malware_alias,
        };
        
        if (entry.confidence !== undefined) {
          formatted["Confidence Level"] = `${entry.confidence}%`;
          const confidence = entry.confidence;
          if (confidence >= 75) formatted["Reliability"] = "High";
          else if (confidence >= 50) formatted["Reliability"] = "Medium";
          else formatted["Reliability"] = "Low";
        }
        
        if (entry.asn) formatted["ASN"] = entry.asn;
        if (entry.country) formatted["Country"] = entry.country;
        if (entry.first_seen) formatted["First Seen"] = entry.first_seen;
        if (entry.last_seen) formatted["Last Seen"] = entry.last_seen;
        if (entry.uuid) formatted["UUID"] = entry.uuid;
        if (entry.reporter) formatted["Reporter"] = entry.reporter;
        if (entry.credits) formatted["Credits"] = `${entry.credits} credits`;
        
        const tags = entry.tags || [];
        if (Array.isArray(tags) && tags.length > 0) {
          formatted["Tags"] = tags.join(", ");
        } else if (tags) {
          formatted["Tags"] = String(tags);
        }
        
        if (entry.reference) formatted["Reference"] = entry.reference;
        
        return formatted;
      });
    }
  
    return { message: "No matching IOCs found." };
  }
  
  export function formatURLHaus(data) {
    if (!data || typeof data !== 'object') return data;
    if (data.error) return data;
    if (data.message) return data;
    
    const result = {};
    
    // Handle search results
    if (data.results?.length > 0) {
      const results = data.results.map(item => {
        const resultItem = {
          "URL": item.url,
          "Host": item.host,
          "Threat Classification": item.threat,
          "Date Added": item.date_added,
          "Reporter": item.reporter,
          "URL Status": item.url_status,
        };
        if (item.tags) {
          resultItem["Tags"] = Array.isArray(item.tags) ? item.tags.join(", ") : item.tags;
        }
        return resultItem;
      });
      return { results, found: true };
    }
    
    // Handle single payload result
    if (data.found) {
      if (data.SHA256) result["SHA256 Hash"] = data.SHA256;
      if (data.MD5) result["MD5 Hash"] = data.MD5;
      if (data["File Size"]) result["File Size"] = data["File Size"];
      if (data["File Type"]) result["File Type"] = data["File Type"];
      if (data["First Seen"]) result["First Seen"] = data["First Seen"];
      if (data["Last Seen"]) result["Last Seen"] = data["Last Seen"];
      if (data["URL Count"]) result["Associated URLs"] = data["URL Count"];
      if (data.URLs?.length > 0) result["Sample URLs"] = data.URLs;
      
      return { ...result, found: true };
    }
    
    return data;
  }
  
  export function formatMalwareBazaar(data) {
    if (!data || typeof data !== 'object') return data;
    if (data.error) return data;
    if (data.message) return data;
    
    const result = {};
    
    // Handle search results
    if (data.results?.length > 0) {
      const results = data.results.map(item => {
        const resultItem = {
          "SHA256 Hash": item.SHA256,
          "File Name": item["File Name"],
          "File Type": item["File Type"],
          "Malware Signature": item.Signature,
          "File Size": item["File Size"],
          "First Seen": item["First Seen"],
          "Reporter": item.Reporter,
        };
        if (item.Tags) {
          resultItem["Tags"] = Array.isArray(item.Tags) ? item.Tags.join(", ") : item.Tags;
        }
        return resultItem;
      });
      return { results, found: true };
    }
    
    // Handle single result
    if (data.found) {
      if (data.SHA256) result["SHA256 Hash"] = data.SHA256;
      if (data["File Name"]) result["File Name"] = data["File Name"];
      if (data["File Type"]) result["MIME Type"] = data["File Type"];
      if (data["File Size"]) {
        result["File Size"] = typeof data["File Size"] === 'number' 
          ? `${data["File Size"].toLocaleString()} bytes` 
          : data["File Size"];
      }
      if (data.Signature) result["Malware Signature"] = data.Signature;
      if (data.Tags) {
        const tags = data.Tags;
        result["Tags"] = Array.isArray(tags) ? tags.join(", ") : String(tags);
      }
      if (data["Delivery Method"]) result["Delivery Method"] = data["Delivery Method"];
      if (data["First Seen"]) result["First Seen"] = data["First Seen"];
      if (data["Last Seen"]) result["Last Seen"] = data["Last Seen"];
      if (data.Reporter) result["Reporter"] = data.Reporter;
      if (data.Comment) result["Comment"] = data.Comment;
      
      // Vendor intelligence
      const vendorIntel = data["Vendor Detections"] || {};
      if (vendorIntel && typeof vendorIntel === 'object') {
        const intelSummary = [];
        for (const [vendor, info] of Object.entries(vendorIntel)) {
          if (typeof info === 'object') {
            if (info.verdict === "MALICIOUS") {
              intelSummary.push(`${vendor}: ${info.verdict}`);
            } else if (info.detection) {
              intelSummary.push(`${vendor}: ${info.detection}`);
            }
          }
        }
        if (intelSummary.length > 0) {
          result["Vendor Intelligence"] = intelSummary.slice(0, 5);
        }
      }
      
      return { ...result, found: true };
    }
    
    return data;
  }
  
  export function formatIPInfo(data) {
    if (!data || typeof data !== 'object') return data;
    if (data.error) return data;
    
    const result = {};
    
    if (data.IP) result["IP Address"] = data.IP;
    if (data.Hostname) result["Hostname"] = data.Hostname;
    if (data.City) result["City"] = data.City;
    if (data.Region) result["Region/State"] = data.Region;
    if (data.Country) result["Country"] = data.Country;
    if (data.Organization) result["Organization"] = data.Organization;
    if (data.ASN) result["ASN"] = data.ASN;
    if (data["⚠️ Resolved Lookup"]) result["Resolution Note"] = data["⚠️ Resolved Lookup"];
    
    return result;
  }
  
  export function formatURLScan(data) {
    // URLScan has complex structure handled in frontend
    return data;
  }