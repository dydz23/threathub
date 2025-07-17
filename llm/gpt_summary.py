import os
import requests
import json
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

class SOCAnalystLLM:
    def __init__(self):
        self.claude_api_key = os.getenv("CLAUDE_API_KEY")
        self.claude_model = "claude-3-5-sonnet-20241022"
        
    def _calculate_risk_score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate preliminary risk score based on threat intelligence data"""
        risk_factors = {
            "malware_detections": 0,
            "reputation_score": 0,
            "threat_feeds": 0,
            "suspicious_activity": 0,
            "geolocation_risk": 0
        }
        
        # Helper function to safely get values
        def safe_get(obj, key, default=0):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return default
        
        # VirusTotal analysis - check formatted data structure
        vt_data = data.get("virustotal", {})
        if isinstance(vt_data, dict) and vt_data.get("Last Analysis Stats"):
            stats = vt_data["Last Analysis Stats"]
            if isinstance(stats, dict):
                malicious = safe_get(stats, "malicious", 0)
                suspicious = safe_get(stats, "suspicious", 0)
                risk_factors["malware_detections"] = min((malicious + suspicious) * 5, 50)
        
        # AbuseIPDB analysis - check for abuse score
        abuse_data = data.get("abuseipdb", {})
        if isinstance(abuse_data, dict):
            abuse_score = safe_get(abuse_data, "Abuse Score", 0)
            if abuse_score > 25:
                risk_factors["reputation_score"] = min(abuse_score, 50)
        
        # Threat feed mentions - check multiple sources
        # ThreatFox
        tf_data = data.get("threatfox", {})
        if isinstance(tf_data, list) and tf_data:
            risk_factors["threat_feeds"] += 20
        elif isinstance(tf_data, dict) and tf_data and not tf_data.get("message"):
            risk_factors["threat_feeds"] += 20
        
        # URLhaus
        urlhaus_data = data.get("urlhaus", {})
        if isinstance(urlhaus_data, dict) and urlhaus_data and not urlhaus_data.get("error") and not urlhaus_data.get("status"):
            risk_factors["threat_feeds"] += 15
        
        # MalwareBazaar
        mb_data = data.get("malwarebazaar", {})
        if isinstance(mb_data, dict) and mb_data and not mb_data.get("error") and not mb_data.get("status"):
            risk_factors["threat_feeds"] += 15
        
        # OTX
        otx_data = data.get("otx", {})
        if isinstance(otx_data, dict) and otx_data and not otx_data.get("error"):
            # Check if OTX has meaningful data
            if otx_data.get("pulse_info") or otx_data.get("general"):
                risk_factors["threat_feeds"] += 10
        
        # Shodan suspicious activity
        shodan_data = data.get("shodan", {})
        if isinstance(shodan_data, dict) and shodan_data:
            ports = shodan_data.get("open_ports", [])
            vulns = shodan_data.get("vulns", [])
            
            if isinstance(ports, list) and len(ports) > 10:
                risk_factors["suspicious_activity"] += 15
            if isinstance(vulns, list) and len(vulns) > 0:
                risk_factors["suspicious_activity"] += 25
        
        # URLScan verdict score
        urlscan_data = data.get("urlscan", {})
        if isinstance(urlscan_data, dict) and urlscan_data.get("summary"):
            verdict_score = urlscan_data.get("summary", {}).get("Verdict Score")
            if verdict_score and isinstance(verdict_score, (int, float)) and verdict_score > 50:
                risk_factors["suspicious_activity"] += 20
        
        total_score = min(sum(risk_factors.values()), 100)
        
        if total_score >= 80:
            risk_level = "HIGH"
        elif total_score >= 50:
            risk_level = "MEDIUM"
        elif total_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "BENIGN"
            
        return {
            "score": total_score,
            "level": risk_level,
            "factors": risk_factors
        }
    
    def _create_enhanced_prompt(self, data: Dict[str, Any], risk_assessment: Dict[str, Any]) -> str:
        """Create enhanced SOC analyst prompt with structured analysis"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        ioc_type = data.get("type", "unknown")
        ioc_value = data.get("input", "unknown")
        
        prompt = f"""You are a Senior SOC Analyst with 5+ years of experience in threat hunting and incident response. 
You have access to multiple threat intelligence sources and need to provide a comprehensive analysis.

ANALYSIS REQUEST:
- Timestamp: {timestamp}
- IOC Type: {ioc_type}
- IOC Value: {ioc_value}
- Preliminary Risk Score: {risk_assessment['score']}/100 ({risk_assessment['level']})

THREAT INTELLIGENCE DATA:
{self._format_threat_data(data)}

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

Focus on actionable intelligence that a SOC team can immediately use for decision-making."""

        return prompt
    
    def _format_threat_data(self, data: Dict[str, Any]) -> str:
        """Format threat intelligence data for better LLM consumption"""
        formatted_sections = []
        
        # Helper function to safely get data
        def safe_get(obj, key, default="N/A"):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return default
        
        # Helper function to format data based on type
        def format_data_section(section_data, source_name):
            if not section_data or (isinstance(section_data, dict) and not section_data):
                return None
                
            if isinstance(section_data, dict) and section_data.get("error"):
                return f"--- {source_name.upper()} ---\nError: {section_data.get('error')}"
            
            if isinstance(section_data, dict) and section_data.get("message"):
                return f"--- {source_name.upper()} ---\nMessage: {section_data.get('message')}"
                
            return f"--- {source_name.upper()} ---\n{json.dumps(section_data, indent=2)}"
        
        # VirusTotal - structured formatting
        vt_data = data.get("virustotal", {})
        if vt_data and not vt_data.get("error"):
            vt_section = f"""--- VIRUSTOTAL ANALYSIS ---
Reputation: {safe_get(vt_data, 'Reputation')}
Type: {safe_get(vt_data, 'Type')}
Last Analysis Stats: {safe_get(vt_data, 'Last Analysis Stats')}
Categories: {safe_get(vt_data, 'Categories')}
First Submission: {safe_get(vt_data, 'First Submission')}
Last Analysis: {safe_get(vt_data, 'Last Analysis')}
Country: {safe_get(vt_data, 'Country')}
ASN: {safe_get(vt_data, 'ASN')}"""
            
            # Add related data if available
            if vt_data.get("Resolved IPs"):
                vt_section += f"\nResolved IPs: {vt_data['Resolved IPs']}"
            if vt_data.get("Communicating Files"):
                vt_section += f"\nCommunicating Files: {len(vt_data['Communicating Files'])} found"
            if vt_data.get("Downloaded Files"):
                vt_section += f"\nDownloaded Files: {len(vt_data['Downloaded Files'])} found"
                
            formatted_sections.append(vt_section)
        
        # AbuseIPDB - structured formatting
        abuse_data = data.get("abuseipdb", {})
        if abuse_data and not abuse_data.get("error"):
            formatted_sections.append(f"""--- ABUSEIPDB REPUTATION ---
IP Address: {safe_get(abuse_data, 'IP Address')}
Abuse Score: {safe_get(abuse_data, 'Abuse Score')}%
Country: {safe_get(abuse_data, 'Country')}
ISP: {safe_get(abuse_data, 'ISP')}
Usage Type: {safe_get(abuse_data, 'Usage Type')}
Total Reports: {safe_get(abuse_data, 'Total Reports')}
Last Reported: {safe_get(abuse_data, 'Last Reported')}""")
        
        # Shodan - structured formatting
        shodan_data = data.get("shodan", {})
        if shodan_data and not shodan_data.get("error"):
            formatted_sections.append(f"""--- SHODAN INFRASTRUCTURE ---
IP: {safe_get(shodan_data, 'ip')}
Organization: {safe_get(shodan_data, 'organization')}
OS: {safe_get(shodan_data, 'os')}
Open Ports: {safe_get(shodan_data, 'open_ports')}
Hostnames: {safe_get(shodan_data, 'hostnames')}
Country: {safe_get(shodan_data, 'country')}
ISP: {safe_get(shodan_data, 'isp')}
Vulnerabilities: {safe_get(shodan_data, 'vulns')}
Tags: {safe_get(shodan_data, 'tags')}""")
        
        # ThreatFox - handle list format
        tf_data = data.get("threatfox", {})
        if tf_data:
            if isinstance(tf_data, list) and tf_data:
                tf_section = "--- THREATFOX INTELLIGENCE ---\n"
                for i, entry in enumerate(tf_data[:3]):  # Limit to first 3 entries
                    if isinstance(entry, dict):
                        tf_section += f"Entry {i+1}:\n"
                        tf_section += f"  IOC: {safe_get(entry, 'IOC')}\n"
                        tf_section += f"  IOC Type: {safe_get(entry, 'IOC Type')}\n"
                        tf_section += f"  Threat Type: {safe_get(entry, 'Threat Type')}\n"
                        tf_section += f"  Malware: {safe_get(entry, 'Malware')}\n"
                        tf_section += f"  Confidence: {safe_get(entry, 'Confidence Level')}\n"
                        tf_section += f"  First Seen: {safe_get(entry, 'First Seen')}\n"
                        tf_section += f"  Tags: {safe_get(entry, 'Tags')}\n\n"
                formatted_sections.append(tf_section)
            elif isinstance(tf_data, dict) and not tf_data.get("message"):
                formatted_sections.append(format_data_section(tf_data, "threatfox"))
        
        # IPInfo - structured formatting
        ipinfo_data = data.get("ipinfo", {})
        if ipinfo_data and not ipinfo_data.get("error"):
            formatted_sections.append(f"""--- IPINFO GEOLOCATION ---
IP: {safe_get(ipinfo_data, 'IP')}
Hostname: {safe_get(ipinfo_data, 'Hostname')}
City: {safe_get(ipinfo_data, 'City')}
Region: {safe_get(ipinfo_data, 'Region')}
Country: {safe_get(ipinfo_data, 'Country')}
Organization: {safe_get(ipinfo_data, 'Organization')}
ASN: {safe_get(ipinfo_data, 'ASN')}""")
        
        # URLScan - structured formatting
        urlscan_data = data.get("urlscan", {})
        if urlscan_data and urlscan_data.get("method") == "active":
            summary = urlscan_data.get("summary", {})
            domain_info = urlscan_data.get("domain_info", {})
            formatted_sections.append(f"""--- URLSCAN ANALYSIS ---
Scan URL: {safe_get(summary, 'Scan URL')}
Verdict Score: {safe_get(summary, 'Verdict Score')}
Verdict Tags: {safe_get(summary, 'Verdict Tags')}
Domain: {safe_get(domain_info, 'Domain')}
IP: {safe_get(domain_info, 'IP')}
Country: {safe_get(domain_info, 'Country')}
ASN: {safe_get(domain_info, 'ASN')}
Screenshot Available: {bool(urlscan_data.get('screenshot'))}""")
        
        # Handle remaining sources with generic formatting
        for source in ["otx", "urlhaus", "malwarebazaar"]:
            source_data = data.get(source, {})
            if source_data:
                section = format_data_section(source_data, source)
                if section:
                    formatted_sections.append(section)
        
        return "\n\n".join(formatted_sections) if formatted_sections else "No threat intelligence data available."
    
    def _call_claude_api(self, prompt: str) -> str:
        """Call Claude API for analysis"""
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.claude_api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        data = {
            "model": self.claude_model,
            "max_tokens": 2000,
            "temperature": 0.1,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                return response.json()['content'][0]['text']
            else:
                return f"[Claude API Error {response.status_code}] {response.text}"
        except Exception as e:
            return f"[Claude API Exception] {str(e)}"
    
    def generate_soc_analysis(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive SOC analyst-level analysis"""
        
        # Calculate risk assessment
        risk_assessment = self._calculate_risk_score(threat_data)
        
        # Create enhanced prompt
        prompt = self._create_enhanced_prompt(threat_data, risk_assessment)
        
        # Get Claude analysis
        llm_analysis = self._call_claude_api(prompt)
        
        # Structure the response
        analysis_result = {
            "timestamp": datetime.now().isoformat(),
            "ioc_type": threat_data.get("type"),
            "ioc_value": threat_data.get("input"),
            "risk_assessment": risk_assessment,
            "llm_analysis": llm_analysis,
            "confidence_level": self._determine_confidence(threat_data),
            "recommended_actions": self._extract_actions(llm_analysis),
            "analyst_notes": "Analysis generated using Claude Sonnet"
        }
        
        return analysis_result
    
    def _determine_confidence(self, data: Dict[str, Any]) -> str:
        """Determine confidence level based on data sources"""
        sources_with_data = 0
        total_sources = len(["virustotal", "abuseipdb", "shodan", "otx", "threatfox", "urlhaus", "malwarebazaar"])
        
        for source in ["virustotal", "abuseipdb", "shodan", "otx", "threatfox", "urlhaus", "malwarebazaar"]:
            if data.get(source) and data[source] != {}:
                sources_with_data += 1
        
        coverage = sources_with_data / total_sources
        
        if coverage >= 0.7:
            return "HIGH"
        elif coverage >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_actions(self, analysis: str) -> list:
        """Extract recommended actions from LLM analysis"""
        # Simple extraction - you can enhance this with NLP
        actions = []
        if "block" in analysis.lower():
            actions.append("BLOCK")
        if "escalate" in analysis.lower():
            actions.append("ESCALATE")
        if "monitor" in analysis.lower():
            actions.append("MONITOR")
        if "investigate" in analysis.lower():
            actions.append("INVESTIGATE")
        
        return actions if actions else ["REVIEW"]


# Updated main function for backwards compatibility
def generate_summary(
    virustotal_data,
    abuseip_data,
    shodan_data,
    otx_data,
    threatfox_data,
    urlhaus_data,
    malwarebazaar_data,
    ipinfo_data,
    urlscan_data,
    raw_data=None
):
    """Backwards compatible function that uses the new SOC analyst approach"""
    
    # Structure data for new analysis
    structured_data = {
        "virustotal": virustotal_data,
        "abuseipdb": abuseip_data,
        "shodan": shodan_data,
        "otx": otx_data,
        "threatfox": threatfox_data,
        "urlhaus": urlhaus_data,
        "malwarebazaar": malwarebazaar_data,
        "ipinfo": ipinfo_data,
        "urlscan": urlscan_data,
        "raw": raw_data
    }
    
    # Initialize SOC analyst LLM
    soc_analyst = SOCAnalystLLM()
    
    # Generate comprehensive analysis
    analysis = soc_analyst.generate_soc_analysis(structured_data)
    
    # Return just the LLM analysis text for backwards compatibility
    return analysis["llm_analysis"]