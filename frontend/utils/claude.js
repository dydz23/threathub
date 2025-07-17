// utils/claude.js
// Converted from llm/gpt_summary.py

export class SOCAnalystLLM {
    constructor() {
      this.claudeApiKey = process.env.CLAUDE_API_KEY;
      this.claudeModel = "claude-3-5-sonnet-20241022";
    }
  
    calculateRiskScore(data) {
      const riskFactors = {
        malware_detections: 0,
        reputation_score: 0,
        threat_feeds: 0,
        suspicious_activity: 0,
        geolocation_risk: 0
      };
  
      const safeGet = (obj, key, defaultValue = 0) => {
        if (typeof obj === 'object' && obj !== null) {
          return obj[key] || defaultValue;
        }
        return defaultValue;
      };
  
      // VirusTotal analysis
      const vtData = data.virustotal || {};
      if (typeof vtData === 'object' && vtData["Last Analysis Stats"]) {
        const stats = vtData["Last Analysis Stats"];
        if (typeof stats === 'object') {
          const malicious = safeGet(stats, "malicious", 0);
          const suspicious = safeGet(stats, "suspicious", 0);
          riskFactors.malware_detections = Math.min((malicious + suspicious) * 5, 50);
        }
      }
  
      // AbuseIPDB analysis
      const abuseData = data.abuseipdb || {};
      if (typeof abuseData === 'object') {
        const abuseScore = safeGet(abuseData, "Abuse Score", 0);
        if (abuseScore > 25) {
          riskFactors.reputation_score = Math.min(abuseScore, 50);
        }
      }
  
      // Threat feed mentions
      const tfData = data.threatfox || {};
      if (Array.isArray(tfData) && tfData.length > 0) {
        riskFactors.threat_feeds += 20;
      } else if (typeof tfData === 'object' && Object.keys(tfData).length > 0 && !tfData.message) {
        riskFactors.threat_feeds += 20;
      }
  
      const urlhausData = data.urlhaus || {};
      if (typeof urlhausData === 'object' && Object.keys(urlhausData).length > 0 && 
          !urlhausData.error && !urlhausData.status) {
        riskFactors.threat_feeds += 15;
      }
  
      const mbData = data.malwarebazaar || {};
      if (typeof mbData === 'object' && Object.keys(mbData).length > 0 && 
          !mbData.error && !mbData.status) {
        riskFactors.threat_feeds += 15;
      }
  
      const otxData = data.otx || {};
      if (typeof otxData === 'object' && Object.keys(otxData).length > 0 && !otxData.error) {
        if (otxData.pulse_info || otxData.general) {
          riskFactors.threat_feeds += 10;
        }
      }
  
      // Shodan suspicious activity
      const shodanData = data.shodan || {};
      if (typeof shodanData === 'object' && Object.keys(shodanData).length > 0) {
        const ports = shodanData.open_ports || [];
        const vulns = shodanData.vulns || [];
  
        if (Array.isArray(ports) && ports.length > 10) {
          riskFactors.suspicious_activity += 15;
        }
        if (Array.isArray(vulns) && vulns.length > 0) {
          riskFactors.suspicious_activity += 25;
        }
      }
  
      // URLScan verdict score
      const urlscanData = data.urlscan || {};
      if (typeof urlscanData === 'object' && urlscanData.summary) {
        const verdictScore = urlscanData.summary["Verdict Score"];
        if (verdictScore && (typeof verdictScore === 'number') && verdictScore > 50) {
          riskFactors.suspicious_activity += 20;
        }
      }
  
      const totalScore = Math.min(Object.values(riskFactors).reduce((a, b) => a + b, 0), 100);
  
      let riskLevel;
      if (totalScore >= 80) riskLevel = "HIGH";
      else if (totalScore >= 50) riskLevel = "MEDIUM";
      else if (totalScore >= 20) riskLevel = "LOW";
      else riskLevel = "BENIGN";
  
      return {
        score: totalScore,
        level: riskLevel,
        factors: riskFactors
      };
    }
  
    createEnhancedPrompt(data, riskAssessment) {
      const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      const iocType = data.type || "unknown";
      const iocValue = data.input || "unknown";
  
      const prompt = `You are a Senior SOC Analyst with 5+ years of experience in threat hunting and incident response. 
  You have access to multiple threat intelligence sources and need to provide a comprehensive analysis.
  
  ANALYSIS REQUEST:
  - Timestamp: ${timestamp}
  - IOC Type: ${iocType}
  - IOC Value: ${iocValue}
  - Preliminary Risk Score: ${riskAssessment.score}/100 (${riskAssessment.level})
  
  THREAT INTELLIGENCE DATA:
  ${this.formatThreatData(data)}
  
  ANALYSIS REQUIREMENTS:
  1. **Executive Summary**: One-sentence verdict on threat level and confidence
  2. **Technical Analysis**: 
     - Correlation across threat intelligence sources
     - Identification of TTPs (if applicable)
     - Attribution indicators (threat groups, campaigns)
  3. **Risk Assessment**:
     - Justify the risk level with specific evidence
     - Potential impact on organization
     - False positive likelihood
  4. **SOC Recommendations**:
     - Immediate actions (block, monitor, escalate)
     - Investigation steps for SOC L1/L2
     - Containment measures if needed
  5. **Context & Attribution**:
     - Geolocation insights
     - Infrastructure analysis
     - Related IOCs or campaigns
  
  RESPONSE FORMAT:
  Use clear headers and bullet points. Be technical but actionable. Include confidence levels (High/Medium/Low) for your assessments.
  
  Focus on actionable intelligence that a SOC team can immediately use for decision-making.`;
  
      return prompt;
    }
  
    formatThreatData(data) {
      const formattedSections = [];
  
      const safeGet = (obj, key, defaultValue = "N/A") => {
        if (typeof obj === 'object' && obj !== null) {
          return obj[key] || defaultValue;
        }
        return defaultValue;
      };
  
      const formatDataSection = (sectionData, sourceName) => {
        if (!sectionData || (typeof sectionData === 'object' && Object.keys(sectionData).length === 0)) {
          return null;
        }
  
        if (typeof sectionData === 'object' && sectionData.error) {
          return `--- ${sourceName.toUpperCase()} ---\nError: ${sectionData.error}`;
        }
  
        if (typeof sectionData === 'object' && sectionData.message) {
          return `--- ${sourceName.toUpperCase()} ---\nMessage: ${sectionData.message}`;
        }
  
        return `--- ${sourceName.toUpperCase()} ---\n${JSON.stringify(sectionData, null, 2)}`;
      };
  
      // VirusTotal - structured formatting
      const vtData = data.virustotal || {};
      if (Object.keys(vtData).length > 0 && !vtData.error) {
        let vtSection = `--- VIRUSTOTAL ANALYSIS ---
  Reputation: ${safeGet(vtData, 'Reputation')}
  Type: ${safeGet(vtData, 'Type')}
  Last Analysis Stats: ${safeGet(vtData, 'Last Analysis Stats')}
  Categories: ${safeGet(vtData, 'Categories')}
  First Submission: ${safeGet(vtData, 'First Submission')}
  Last Analysis: ${safeGet(vtData, 'Last Analysis')}
  Country: ${safeGet(vtData, 'Country')}
  ASN: ${safeGet(vtData, 'ASN')}`;
  
        if (vtData["Resolved IPs"]) {
          vtSection += `\nResolved IPs: ${vtData["Resolved IPs"]}`;
        }
        if (vtData["Communicating Files"]) {
          vtSection += `\nCommunicating Files: ${vtData["Communicating Files"].length} found`;
        }
        if (vtData["Downloaded Files"]) {
          vtSection += `\nDownloaded Files: ${vtData["Downloaded Files"].length} found`;
        }
  
        formattedSections.push(vtSection);
      }
  
      // AbuseIPDB - structured formatting
      const abuseData = data.abuseipdb || {};
      if (Object.keys(abuseData).length > 0 && !abuseData.error) {
        formattedSections.push(`--- ABUSEIPDB REPUTATION ---
  IP Address: ${safeGet(abuseData, 'IP Address')}
  Abuse Score: ${safeGet(abuseData, 'Abuse Score')}%
  Country: ${safeGet(abuseData, 'Country')}
  ISP: ${safeGet(abuseData, 'ISP')}
  Usage Type: ${safeGet(abuseData, 'Usage Type')}
  Total Reports: ${safeGet(abuseData, 'Total Reports')}
  Last Reported: ${safeGet(abuseData, 'Last Reported')}`);
      }
  
      // Shodan - structured formatting
      const shodanData = data.shodan || {};
      if (Object.keys(shodanData).length > 0 && !shodanData.error) {
        formattedSections.push(`--- SHODAN INFRASTRUCTURE ---
  IP: ${safeGet(shodanData, 'ip')}
  Organization: ${safeGet(shodanData, 'organization')}
  OS: ${safeGet(shodanData, 'os')}
  Open Ports: ${safeGet(shodanData, 'open_ports')}
  Hostnames: ${safeGet(shodanData, 'hostnames')}
  Country: ${safeGet(shodanData, 'country')}
  ISP: ${safeGet(shodanData, 'isp')}
  Vulnerabilities: ${safeGet(shodanData, 'vulns')}
  Tags: ${safeGet(shodanData, 'tags')}`);
      }
  
      // ThreatFox - handle list format
      const tfData = data.threatfox || {};
      if (Object.keys(tfData).length > 0) {
        if (Array.isArray(tfData) && tfData.length > 0) {
          let tfSection = "--- THREATFOX INTELLIGENCE ---\n";
          for (let i = 0; i < Math.min(tfData.length, 3); i++) {
            const entry = tfData[i];
            if (typeof entry === 'object') {
              tfSection += `Entry ${i + 1}:\n`;
              tfSection += `  IOC: ${safeGet(entry, 'IOC')}\n`;
              tfSection += `  IOC Type: ${safeGet(entry, 'IOC Type')}\n`;
              tfSection += `  Threat Type: ${safeGet(entry, 'Threat Type')}\n`;
              tfSection += `  Malware: ${safeGet(entry, 'Malware')}\n`;
              tfSection += `  Confidence: ${safeGet(entry, 'Confidence Level')}\n`;
              tfSection += `  First Seen: ${safeGet(entry, 'First Seen')}\n`;
              tfSection += `  Tags: ${safeGet(entry, 'Tags')}\n\n`;
            }
          }
          formattedSections.push(tfSection);
        } else if (typeof tfData === 'object' && !tfData.message) {
          const section = formatDataSection(tfData, "threatfox");
          if (section) formattedSections.push(section);
        }
      }
  
      // IPInfo - structured formatting
      const ipinfoData = data.ipinfo || {};
      if (Object.keys(ipinfoData).length > 0 && !ipinfoData.error) {
        formattedSections.push(`--- IPINFO GEOLOCATION ---
  IP: ${safeGet(ipinfoData, 'IP')}
  Hostname: ${safeGet(ipinfoData, 'Hostname')}
  City: ${safeGet(ipinfoData, 'City')}
  Region: ${safeGet(ipinfoData, 'Region')}
  Country: ${safeGet(ipinfoData, 'Country')}
  Organization: ${safeGet(ipinfoData, 'Organization')}
  ASN: ${safeGet(ipinfoData, 'ASN')}`);
      }
  
      // URLScan - structured formatting
      const urlscanData = data.urlscan || {};
      if (urlscanData.method === "active") {
        const summary = urlscanData.summary || {};
        const domainInfo = urlscanData.domain_info || {};
        formattedSections.push(`--- URLSCAN ANALYSIS ---
  Scan URL: ${safeGet(summary, 'Scan URL')}
  Verdict Score: ${safeGet(summary, 'Verdict Score')}
  Verdict Tags: ${safeGet(summary, 'Verdict Tags')}
  Domain: ${safeGet(domainInfo, 'Domain')}
  IP: ${safeGet(domainInfo, 'IP')}
  Country: ${safeGet(domainInfo, 'Country')}
  ASN: ${safeGet(domainInfo, 'ASN')}
  Screenshot Available: ${!!urlscanData.screenshot}`);
      }
  
      // Handle remaining sources with generic formatting
      ['otx', 'urlhaus', 'malwarebazaar'].forEach(source => {
        const sourceData = data[source] || {};
        if (Object.keys(sourceData).length > 0) {
          const section = formatDataSection(sourceData, source);
          if (section) formattedSections.push(section);
        }
      });
  
      return formattedSections.length > 0 ? formattedSections.join('\n\n') : "No threat intelligence data available.";
    }
  
    async callClaudeAPI(prompt) {
      const url = "https://api.anthropic.com/v1/messages";
      const headers = {
        "x-api-key": this.claudeApiKey,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01"
      };
  
      const data = {
        model: this.claudeModel,
        max_tokens: 2000,
        temperature: 0.1,
        messages: [
          {
            role: "user",
            content: prompt
          }
        ]
      };
  
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(data)
        });
  
        if (response.ok) {
          const result = await response.json();
          return result.content[0].text;
        } else {
          const errorText = await response.text();
          return `[Claude API Error ${response.status}] ${errorText}`;
        }
      } catch (error) {
        return `[Claude API Exception] ${error.message}`;
      }
    }
  
    async generateSOCAnalysis(threatData) {
      // Calculate risk assessment
      const riskAssessment = this.calculateRiskScore(threatData);
  
      // Create enhanced prompt
      const prompt = this.createEnhancedPrompt(threatData, riskAssessment);
  
      // Get Claude analysis
      const llmAnalysis = await this.callClaudeAPI(prompt);
  
      // Structure the response
      const analysisResult = {
        timestamp: new Date().toISOString(),
        ioc_type: threatData.type,
        ioc_value: threatData.input,
        risk_assessment: riskAssessment,
        llm_analysis: llmAnalysis,
        confidence_level: this.determineConfidence(threatData),
        recommended_actions: this.extractActions(llmAnalysis),
        analyst_notes: "Analysis generated using Claude Sonnet"
      };
  
      return analysisResult;
    }
  
    determineConfidence(data) {
      let sourcesWithData = 0;
      const totalSources = 7; // virustotal, abuseipdb, shodan, otx, threatfox, urlhaus, malwarebazaar
  
      ['virustotal', 'abuseipdb', 'shodan', 'otx', 'threatfox', 'urlhaus', 'malwarebazaar'].forEach(source => {
        const sourceData = data[source];
        if (sourceData && typeof sourceData === 'object' && Object.keys(sourceData).length > 0) {
          sourcesWithData++;
        }
      });
  
      const coverage = sourcesWithData / totalSources;
  
      if (coverage >= 0.7) return "HIGH";
      if (coverage >= 0.4) return "MEDIUM";
      return "LOW";
    }
  
    extractActions(analysis) {
      const actions = [];
      const lowerAnalysis = analysis.toLowerCase();
  
      if (lowerAnalysis.includes("block")) actions.push("BLOCK");
      if (lowerAnalysis.includes("escalate")) actions.push("ESCALATE");
      if (lowerAnalysis.includes("monitor")) actions.push("MONITOR");
      if (lowerAnalysis.includes("investigate")) actions.push("INVESTIGATE");
  
      return actions.length > 0 ? actions : ["REVIEW"];
    }
  }
  
  // Backwards compatible function
  export async function generateSummary(
    virusTotalData,
    abuseIpData,
    shodanData,
    otxData,
    threatfoxData,
    urlhausData,
    malwareBazaarData,
    ipinfoData,
    urlscanData,
    rawData = null
  ) {
    // Structure data for new analysis
    const structuredData = {
      virustotal: virusTotalData,
      abuseipdb: abuseIpData,
      shodan: shodanData,
      otx: otxData,
      threatfox: threatfoxData,
      urlhaus: urlhausData,
      malwarebazaar: malwareBazaarData,
      ipinfo: ipinfoData,
      urlscan: urlscanData,
      raw: rawData
    };
  
    // Initialize SOC analyst LLM
    const socAnalyst = new SOCAnalystLLM();
  
    // Generate comprehensive analysis
    const analysis = await socAnalyst.generateSOCAnalysis(structuredData);
  
    // Return just the LLM analysis text for backwards compatibility
    return analysis.llm_analysis;
  }