// api/sources.js
export default async function handler(req, res) {
    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    return res.status(200).json({
      sources: [
        {
          name: "VirusTotal",
          type: "Multi-engine malware scanner",
          supported_iocs: ["ip", "domain", "hash", "url"]
        },
        {
          name: "AbuseIPDB",
          type: "IP reputation database",
          supported_iocs: ["ip"]
        },
        {
          name: "Shodan",
          type: "Internet-connected device search",
          supported_iocs: ["ip"]
        },
        {
          name: "AlienVault OTX",
          type: "Threat intelligence platform",
          supported_iocs: ["ip", "domain", "hash"]
        },
        {
          name: "ThreatFox",
          type: "Malware IOC database",
          supported_iocs: ["ip", "domain", "hash"]
        },
        {
          name: "URLhaus",
          type: "Malware URL database",
          supported_iocs: ["hash", "url"]
        },
        {
          name: "MalwareBazaar",
          type: "Malware sample database",
          supported_iocs: ["hash"]
        },
        {
          name: "IPInfo",
          type: "IP geolocation service",
          supported_iocs: ["ip"]
        },
        {
          name: "URLScan",
          type: "URL analysis service",
          supported_iocs: ["url", "domain"]
        }
      ],
      analyst_capabilities: [
        "Risk assessment and scoring",
        "Multi-source correlation",
        "TTPs identification",
        "Threat attribution",
        "Actionable recommendations",
        "Confidence assessment"
      ],
      timestamp: new Date().toISOString()
    });
  }
  