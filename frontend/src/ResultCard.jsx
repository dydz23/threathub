import { useState } from "react";

const formatKey = (key) =>
  key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (str) => str.toUpperCase());

const badgeClass = (value) => {
  if (typeof value !== "string") return "bg-gray-300";
  const val = value.toLowerCase();
  if (["malicious", "bad", "phishing", "c2"].some((s) => val.includes(s))) return "bg-red-600";
  if (["suspicious", "unknown", "risk", "unusual"].some((s) => val.includes(s))) return "bg-yellow-500";
  if (["benign", "clean", "safe"].some((s) => val.includes(s))) return "bg-green-600";
  return "bg-gray-400";
};

const getRiskBadgeColor = (level) => {
  switch (level?.toUpperCase()) {
    case "HIGH": return "bg-red-600";
    case "MEDIUM": return "bg-yellow-500";
    case "LOW": return "bg-blue-500";
    case "BENIGN": return "bg-green-600";
    default: return "bg-gray-400";
  }
};

const getConfidenceBadgeColor = (level) => {
  switch (level?.toUpperCase()) {
    case "HIGH": return "bg-green-600";
    case "MEDIUM": return "bg-yellow-500";
    case "LOW": return "bg-red-500";
    default: return "bg-gray-400";
  }
};

// Helper function to generate platform URLs
const generatePlatformURL = (platform, iocValue, iocType) => {
  const cleanIOC = encodeURIComponent(iocValue);
  
  switch (platform) {
    case 'virustotal':
      if (iocType === 'hash') {
        return `https://www.virustotal.com/gui/file/${cleanIOC}`;
      } else if (iocType === 'ip') {
        return `https://www.virustotal.com/gui/ip-address/${cleanIOC}`;
      } else if (iocType === 'domain') {
        return `https://www.virustotal.com/gui/domain/${cleanIOC}`;
      } else if (iocType === 'url') {
        return `https://www.virustotal.com/gui/url/${btoa(iocValue)}/detection`;
      }
      return `https://www.virustotal.com/gui/search/${cleanIOC}`;
      
    case 'abuseipdb':
      return `https://www.abuseipdb.com/check/${cleanIOC}`;
      
    case 'shodan':
      return `https://www.shodan.io/host/${cleanIOC}`;
      
    case 'otx':
      if (iocType === 'ip') {
        return `https://otx.alienvault.com/indicator/ip/${cleanIOC}`;
      } else if (iocType === 'domain') {
        return `https://otx.alienvault.com/indicator/domain/${cleanIOC}`;
      } else if (iocType === 'hash') {
        return `https://otx.alienvault.com/indicator/file/${cleanIOC}`;
      }
      return `https://otx.alienvault.com/browse/global/pulses?q=${cleanIOC}`;
      
    case 'threatfox':
      return `https://threatfox.abuse.ch/browse.php?search=ioc%3A${cleanIOC}`;
      
    case 'urlhaus':
      if (iocType === 'hash') {
        return `https://urlhaus.abuse.ch/browse.php?search=${cleanIOC}`;
      }
      return `https://urlhaus.abuse.ch/browse.php?search=${cleanIOC}`;
      
    case 'malwarebazaar':
      return `https://bazaar.abuse.ch/browse.php?search=${cleanIOC}`;
      
    case 'ipinfo':
      return `https://ipinfo.io/${cleanIOC}`;
      
    case 'urlscan':
      return `https://urlscan.io/search/#${cleanIOC}`;
      
    default:
      return null;
  }
};

// Platform button component
const PlatformButton = ({ platform, iocValue, iocType, platformName }) => {
  const url = generatePlatformURL(platform, iocValue, iocType);
  
  if (!url) return null;
  
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center px-3 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors"
    >
      <span className="mr-2">🔗</span>
      View on {platformName}
    </a>
  );
};
const formatValue = (value) => {
  if (value === null || value === undefined) {
    return <span className="text-gray-400 italic">N/A</span>;
  }
  
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-gray-400 italic">None</span>;
    }
    return (
      <div className="space-y-1">
        {value.map((item, index) => (
          <span key={index} className="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded mr-1 mb-1">
            {String(item)}
          </span>
        ))}
      </div>
    );
  }
  
  if (typeof value === 'object' && value !== null) {
    return (
      <pre className="whitespace-pre-wrap text-xs bg-gray-50 p-2 rounded border">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  }
  
  // Format URLs as clickable links
  if (typeof value === 'string' && (value.startsWith('http://') || value.startsWith('https://'))) {
    return (
      <a 
        href={value} 
        target="_blank" 
        rel="noopener noreferrer" 
        className="text-blue-600 hover:text-blue-800 underline break-all"
      >
        {value}
      </a>
    );
  }
  
  // Highlight important status values
  if (typeof value === 'string') {
    const lowerValue = value.toLowerCase();
    if (['malicious', 'malware', 'bad', 'infected'].some(term => lowerValue.includes(term))) {
      return <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs font-medium">{value}</span>;
    }
    if (['suspicious', 'warning', 'medium'].some(term => lowerValue.includes(term))) {
      return <span className="bg-yellow-100 text-yellow-800 px-2 py-1 rounded text-xs font-medium">{value}</span>;
    }
    if (['clean', 'safe', 'benign', 'good'].some(term => lowerValue.includes(term))) {
      return <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-xs font-medium">{value}</span>;
    }
  }
  
  return String(value);
};

const JSONTable = ({ data, sourceTitle, iocValue, iocType }) => {
  if (!data || Object.keys(data).length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <div className="text-4xl mb-2">🔍</div>
        <p className="font-medium">No data available</p>
        <p className="text-sm">No results found for this IOC</p>
      </div>
    );
  }

  // Handle error states
  if (data.error) {
    return (
      <div className="text-center py-8 text-red-500">
        <div className="text-4xl mb-2">⚠️</div>
        <p className="font-medium">Error</p>
        <p className="text-sm">{data.error}</p>
      </div>
    );
  }

  // Handle message states
  if (data.message && !data.found) {
    return (
      <div className="text-center py-8 text-gray-500">
        <div className="text-4xl mb-2">📄</div>
        <p className="font-medium">No Results</p>
        <p className="text-sm">{data.message}</p>
      </div>
    );
  }

  // Get platform name from sourceTitle
  const platformName = sourceTitle || 'Platform';
  const platformKey = platformName.toLowerCase().replace(/\s+/g, '');

  // Special handling for ThreatFox results (list format)
  if (Array.isArray(data) && data.length > 0) {
    return (
      <div className="space-y-4">
        {/* Platform Button */}
        <div className="flex justify-end">
          <PlatformButton 
            platform="threatfox" 
            iocValue={iocValue} 
            iocType={iocType}
            platformName="ThreatFox"
          />
        </div>
        
        {data.map((item, index) => (
          <div key={index} className="border border-gray-200 rounded-lg overflow-hidden">
            <div className="bg-gray-50 px-4 py-2 border-b">
              <h4 className="font-medium text-gray-800">Entry {index + 1}</h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <tbody>
                  {Object.entries(item).map(([key, value]) => (
                    <tr key={key} className="border-b border-gray-100 last:border-b-0">
                      <td className="px-4 py-3 font-medium text-gray-700 bg-gray-50 w-1/3">
                        {formatKey(key)}
                      </td>
                      <td className="px-4 py-3 text-gray-900 break-all">
                        {formatValue(value)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>
    );
  }

  // Handle results with nested data
  if (data.results && Array.isArray(data.results)) {
    return (
      <div className="space-y-4">
        {/* Platform Button */}
        <div className="flex justify-between items-center">
          <div className="bg-green-50 border border-green-200 rounded-lg p-3 flex-1 mr-4">
            <div className="flex items-center">
              <div className="text-green-600 mr-2">✅</div>
              <span className="font-medium text-green-800">
                Found {data.results.length} result{data.results.length !== 1 ? 's' : ''}
              </span>
            </div>
          </div>
          <PlatformButton 
            platform={platformKey} 
            iocValue={iocValue} 
            iocType={iocType}
            platformName={platformName}
          />
        </div>
        
        {data.results.map((item, index) => (
          <div key={index} className="border border-gray-200 rounded-lg overflow-hidden">
            <div className="bg-gray-50 px-4 py-2 border-b">
              <h4 className="font-medium text-gray-800">Result {index + 1}</h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <tbody>
                  {Object.entries(item).map(([key, value]) => (
                    <tr key={key} className="border-b border-gray-100 last:border-b-0">
                      <td className="px-4 py-3 font-medium text-gray-700 bg-gray-50 w-1/3">
                        {formatKey(key)}
                      </td>
                      <td className="px-4 py-3 text-gray-900 break-all">
                        {formatValue(value)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>
    );
  }

  // Standard table format for single results
  return (
    <div className="space-y-4">
      {/* Header with Found indicator and Platform Button */}
      <div className="flex justify-between items-center">
        {data.found && (
          <div className="bg-green-50 border border-green-200 rounded-lg px-4 py-2 flex-1 mr-4">
            <div className="flex items-center">
              <div className="text-green-600 mr-2">✅</div>
              <span className="font-medium text-green-800">Data Found</span>
            </div>
          </div>
        )}
        <PlatformButton 
          platform={platformKey} 
          iocValue={iocValue} 
          iocType={iocType}
          platformName={platformName}
        />
      </div>
      
      {/* Data Table */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <tbody>
              {Object.entries(data)
                .filter(([key]) => !['found', 'message', 'error'].includes(key))
                .map(([key, value]) => (
                  <tr key={key} className="border-b border-gray-100 last:border-b-0">
                    <td className="px-4 py-3 font-medium text-gray-700 bg-gray-50 w-1/3">
                      {formatKey(key)}
                    </td>
                    <td className="px-4 py-3 text-gray-900 break-all">
                      {formatValue(value)}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const IOCCompatibilityMatrix = ({ currentIOCType }) => {
  const platforms = [
    {
      name: "VirusTotal",
      icon: "🧬",
      supported: ["ip", "domain", "url", "hash"],
      description: "Multi-engine scanner"
    },
    {
      name: "AbuseIPDB", 
      icon: "🚨",
      supported: ["ip"],
      description: "IP reputation database"
    },
    {
      name: "Shodan",
      icon: "🔍", 
      supported: ["ip"],
      description: "Internet device search"
    },
    {
      name: "AlienVault OTX",
      icon: "🛰️",
      supported: ["ip", "domain", "hash"],
      description: "Threat intelligence platform"
    },
    {
      name: "ThreatFox",
      icon: "🦊",
      supported: ["ip", "domain", "hash", "threatfox_query"],
      description: "Malware IOC database"
    },
    {
      name: "URLhaus",
      icon: "🌐",
      supported: ["hash", "url"],
      description: "Malware URL database"
    },
    {
      name: "MalwareBazaar",
      icon: "🦠",
      supported: ["hash"],
      description: "Malware sample database"
    },
    {
      name: "IPInfo",
      icon: "📌",
      supported: ["ip"],
      description: "IP geolocation service"
    },
    {
      name: "URLScan",
      icon: "📸",
      supported: ["url", "domain"],
      description: "URL analysis service"
    }
  ];

  const iocTypes = {
    "ip": { label: "IP Address", color: "blue", examples: ["8.8.8.8", "192.168.1.1"] },
    "domain": { label: "Domain", color: "green", examples: ["example.com", "malicious.site"] },
    "url": { label: "URL", color: "purple", examples: ["https://example.com/malware", "http://evil.com"] },
    "hash": { label: "File Hash", color: "orange", examples: ["MD5, SHA1, SHA256", "d41d8cd98f00b204e9800998ecf8427e"] },
    "threatfox_query": { label: "ThreatFox Query", color: "red", examples: ["malware:emotet", "tag:apt29"] }
  };

  const getCompatibilityColor = (platformSupported, iocType) => {
    if (platformSupported.includes(iocType)) {
      return currentIOCType === iocType ? "bg-green-500" : "bg-green-200";
    }
    return "bg-gray-200";
  };

  const getTextColor = (platformSupported, iocType) => {
    if (platformSupported.includes(iocType)) {
      return currentIOCType === iocType ? "text-white" : "text-green-800";
    }
    return "text-gray-400";
  };

  return (
    <div className="space-y-6">
      {/* Current IOC Type Header */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-blue-800 mb-2">
          📋 IOC Compatibility Matrix
        </h3>
        <p className="text-blue-700 text-sm">
          See which threat intelligence platforms support different IOC types. 
          {currentIOCType && (
            <span className="font-medium"> Current IOC type: {iocTypes[currentIOCType]?.label || currentIOCType}</span>
          )}
        </p>
      </div>

      {/* IOC Types Legend */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {Object.entries(iocTypes).map(([type, info]) => (
          <div key={type} className={`border rounded-lg p-3 ${currentIOCType === type ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
            <div className="flex items-center mb-2">
              <span className={`inline-block w-3 h-3 rounded-full mr-2 bg-${info.color}-500`}></span>
              <h4 className="font-medium text-gray-800">{info.label}</h4>
            </div>
            <div className="text-xs text-gray-600 space-y-1">
              {info.examples.map((example, index) => (
                <div key={index} className="bg-gray-100 px-2 py-1 rounded font-mono">
                  {example}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Compatibility Matrix */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="bg-gray-50 px-4 py-3 border-b">
          <h4 className="font-medium text-gray-800">Platform Compatibility</h4>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50">
                <th className="text-left px-4 py-3 font-medium text-gray-700 border-b">Platform</th>
                {Object.entries(iocTypes).map(([type, info]) => (
                  <th key={type} className="text-center px-2 py-3 font-medium text-gray-700 border-b min-w-[80px]">
                    <div className="flex flex-col items-center">
                      <span className={`inline-block w-2 h-2 rounded-full mb-1 bg-${info.color}-500`}></span>
                      <span className="text-xs">{info.label}</span>
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {platforms.map((platform) => (
                <tr key={platform.name} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center">
                      <span className="text-lg mr-2">{platform.icon}</span>
                      <div>
                        <div className="font-medium text-gray-800">{platform.name}</div>
                        <div className="text-xs text-gray-500">{platform.description}</div>
                      </div>
                    </div>
                  </td>
                  {Object.keys(iocTypes).map((iocType) => (
                    <td key={iocType} className="text-center px-2 py-3">
                      <div className={`w-6 h-6 rounded-full mx-auto flex items-center justify-center ${getCompatibilityColor(platform.supported, iocType)}`}>
                        {platform.supported.includes(iocType) ? (
                          <span className={`text-xs ${getTextColor(platform.supported, iocType)}`}>✓</span>
                        ) : (
                          <span className="text-xs text-gray-400">−</span>
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Legend */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h4 className="font-medium text-gray-800 mb-2">Legend</h4>
        <div className="flex flex-wrap gap-4 text-sm">
          <div className="flex items-center">
            <div className="w-4 h-4 bg-green-500 rounded-full mr-2"></div>
            <span>Supports current IOC type</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-green-200 rounded-full mr-2"></div>
            <span>Supports IOC type</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-gray-200 rounded-full mr-2"></div>
            <span>Does not support</span>
          </div>
        </div>
      </div>
    </div>
  );
};

const SOCAnalysisTab = ({ socAnalysis, metadata }) => {
  if (!socAnalysis) {
    return <p className="text-gray-500 italic">No SOC analysis available.</p>;
  }

  return (
    <div className="space-y-6">
      {/* Risk Assessment Header */}
      <div className="bg-gray-50 p-4 rounded-lg border">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-800">🎯 Risk Assessment</h3>
          <div className="flex gap-3">
            <span className={`px-3 py-1 rounded-full text-white text-sm font-medium ${getRiskBadgeColor(metadata?.risk_level)}`}>
              Risk: {metadata?.risk_level || 'Unknown'}
            </span>
            <span className={`px-3 py-1 rounded-full text-white text-sm font-medium ${getConfidenceBadgeColor(metadata?.confidence_level)}`}>
              Confidence: {metadata?.confidence_level || 'Unknown'}
            </span>
          </div>
        </div>
        
        {/* Risk Score Bar */}
        <div className="mb-3">
          <div className="flex justify-between text-sm text-gray-600 mb-1">
            <span>Risk Score</span>
            <span>{metadata?.risk_score || 0}/100</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-3">
            <div 
              className={`h-3 rounded-full transition-all duration-300 ${getRiskBadgeColor(metadata?.risk_level)}`}
              style={{ width: `${metadata?.risk_score || 0}%` }}
            ></div>
          </div>
        </div>

        {/* Recommended Actions */}
        {metadata?.recommended_actions && metadata.recommended_actions.length > 0 && (
          <div>
            <h4 className="font-medium text-gray-700 mb-2">🚨 Recommended Actions:</h4>
            <div className="flex gap-2 flex-wrap">
              {metadata.recommended_actions.map((action, index) => (
                <span key={index} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-sm">
                  {action}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* SOC Analysis */}
      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-lg font-semibold text-gray-800 mb-3 flex items-center">
          👨‍💻 SOC Analyst Assessment
        </h3>
        <div className="prose prose-sm max-w-none">
          <pre className="whitespace-pre-wrap font-sans text-gray-700 leading-relaxed">
            {socAnalysis.llm_analysis || 'No analysis available'}
          </pre>
        </div>
      </div>

      {/* Analysis Metadata */}
      {socAnalysis && (
        <div className="bg-gray-50 p-4 rounded-lg border">
          <h4 className="font-medium text-gray-700 mb-3">📊 Analysis Details</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium text-gray-600">IOC Type:</span>
              <span className="ml-2">{socAnalysis.ioc_type || 'Unknown'}</span>
            </div>
            <div>
              <span className="font-medium text-gray-600">IOC Value:</span>
              <span className="ml-2 break-all">{socAnalysis.ioc_value || 'Unknown'}</span>
            </div>
            <div>
              <span className="font-medium text-gray-600">Analysis Time:</span>
              <span className="ml-2">
                {socAnalysis.timestamp ? new Date(socAnalysis.timestamp).toLocaleString() : 'Unknown'}
              </span>
            </div>
            <div>
              <span className="font-medium text-gray-600">Analyst Engine:</span>
              <span className="ml-2">{socAnalysis.analyst_notes || 'Claude Sonnet'}</span>
            </div>
          </div>
          
          {/* Risk Factors Breakdown */}
          {socAnalysis.risk_assessment?.factors && (
            <div className="mt-4">
              <h5 className="font-medium text-gray-600 mb-2">Risk Factors Breakdown:</h5>
              <div className="space-y-1">
                {Object.entries(socAnalysis.risk_assessment.factors).map(([factor, score]) => (
                  <div key={factor} className="flex justify-between text-sm">
                    <span className="capitalize">{factor.replace(/_/g, ' ')}:</span>
                    <span className="font-medium">{score}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const ResultCard = ({ result }) => {
  const [tab, setTab] = useState("soc_analysis");

  // Legacy risk assessment for backwards compatibility
  const abuseScore = result.abuseipdb?.["Abuse Score"] || 0;
  const getLegacyRiskLevel = () => {
    if (abuseScore >= 70) return { label: "High", color: "red" };
    if (abuseScore >= 30) return { label: "Moderate", color: "yellow" };
    return { label: "Low", color: "green" };
  };

  const legacyRisk = getLegacyRiskLevel();

  // Use new metadata if available, fall back to legacy
  const currentRisk = result.metadata?.risk_level || legacyRisk.label;
  const riskScore = result.metadata?.risk_score || abuseScore;

  const allTabs = [
    "soc_analysis",
    "compatibility",
    "summary", 
    "virustotal",
    "abuseipdb",
    "shodan",
    "otx",
    "threatfox",
    "urlhaus",
    "malwarebazaar",
    "ipinfo",
    "urlscan"
  ];

  const tabIcons = {
    soc_analysis: "🧠",
    compatibility: "📊",
    summary: "📝",
    virustotal: "🧬",
    abuseipdb: "🚨",
    shodan: "🔍",
    otx: "🛰️",
    threatfox: "🦊",
    urlhaus: "🌐",
    malwarebazaar: "🦠",
    ipinfo: "📌",
    urlscan: "📸"
  };

  const renderContent = () => {
    if (tab === "soc_analysis") {
      return <SOCAnalysisTab socAnalysis={result.soc_analysis} metadata={result.metadata} />;
    }

    if (tab === "compatibility") {
      return <IOCCompatibilityMatrix currentIOCType={result.type} />;
    }

    if (tab === "summary") {
      return (
        <>
          <div className={`inline-block px-3 py-1 rounded text-white text-sm mb-4 ${getRiskBadgeColor(currentRisk)}`}>
            Risk Level: {currentRisk} ({riskScore}/100)
          </div>
          <p className="whitespace-pre-line mt-2">{result.summary}</p>
        </>
      );
    }

    if (tab === "urlscan") {
      const data = result.urlscan;

      if (!data || data.method !== "active" || !data.summary) {
        return (
          <div className="text-center py-8 text-gray-500">
            <div className="text-4xl mb-2">🔍</div>
            <p className="font-medium">No URLScan Results</p>
            <p className="text-sm">No active scan results available</p>
          </div>
        );
      }

      const { summary, domain_info, http, screenshot, reportURL } = data;

      return (
        <div className="space-y-6">
          {/* Screenshot */}
          {screenshot && (
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b">
                <h3 className="font-medium text-gray-800">📸 Website Screenshot</h3>
              </div>
              <div className="p-4">
                <img
                  src={screenshot}
                  alt="Website Screenshot"
                  className="w-full rounded shadow-md max-h-96 object-contain border"
                />
              </div>
            </div>
          )}

          {/* Scan Summary */}
          {summary && (
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b">
                <h3 className="font-medium text-gray-800">📊 Scan Summary</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <tbody>
                    {Object.entries(summary).map(([key, value]) => (
                      <tr key={key} className="border-b border-gray-100 last:border-b-0">
                        <td className="px-4 py-3 font-medium text-gray-700 bg-gray-50 w-1/3">
                          {formatKey(key)}
                        </td>
                        <td className="px-4 py-3 text-gray-900">
                          {formatValue(value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Domain Information */}
          {domain_info && (
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b">
                <h3 className="font-medium text-gray-800">🌐 Domain & IP Information</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <tbody>
                    {Object.entries(domain_info).map(([key, value]) => (
                      <tr key={key} className="border-b border-gray-100 last:border-b-0">
                        <td className="px-4 py-3 font-medium text-gray-700 bg-gray-50 w-1/3">
                          {formatKey(key)}
                        </td>
                        <td className="px-4 py-3 text-gray-900">
                          {formatValue(value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* HTTP Analysis */}
          {(http?.Redirects?.length > 0 || http?.Indicators || http?.Behaviors) && (
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b">
                <h3 className="font-medium text-gray-800">🔄 HTTP Analysis</h3>
              </div>
              <div className="p-4 space-y-4">
                {/* Redirects */}
                {http?.Redirects?.length > 0 && (
                  <div>
                    <h4 className="font-medium text-gray-700 mb-2">Redirects</h4>
                    <div className="space-y-2">
                      {http.Redirects.map((url, index) => (
                        <div key={index} className="bg-gray-50 p-2 rounded border">
                          <span className="text-sm text-gray-600 mr-2">{index + 1}.</span>
                          <a 
                            href={url} 
                            target="_blank" 
                            rel="noopener noreferrer" 
                            >
                            {url}
                          </a>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Indicators and Behaviors */}
                {(http?.Indicators || http?.Behaviors) && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {http?.Indicators && Object.keys(http.Indicators).length > 0 && (
                      <div>
                        <h4 className="font-medium text-gray-700 mb-2">Indicators</h4>
                        <div className="space-y-1">
                          {Object.entries(http.Indicators).map(([key, value]) => (
                            <div key={key} className="flex justify-between text-sm">
                              <span className="text-gray-600">{formatKey(key)}:</span>
                              <span>{formatValue(value)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {http?.Behaviors && Object.keys(http.Behaviors).length > 0 && (
                      <div>
                        <h4 className="font-medium text-gray-700 mb-2">Behaviors</h4>
                        <div className="space-y-1">
                          {Object.entries(http.Behaviors).map(([key, value]) => (
                            <div key={key} className="flex justify-between text-sm">
                              <span className="text-gray-600">{formatKey(key)}:</span>
                              <span>{formatValue(value)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Report Link */}
          {reportURL && (
            <div className="text-center">
              <a
                href={reportURL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <span className="mr-2">📄</span>
                View Full Report on URLScan.io
              </a>
            </div>
          )}
        </div>
      );
    }

    return <JSONTable 
      data={result[tab]} 
      sourceTitle={formatKey(tab)} 
      iocValue={result.input}
      iocType={result.type}
    />;
  };

  return (
    <div className="mt-6 p-4 bg-white rounded shadow border">
      {/* Header with IOC info */}
      <div className="mb-4 pb-3 border-b">
        <div className="flex justify-between items-start">
          <div className="flex-1">
            <h2 className="text-lg font-semibold text-gray-800 mb-1">
              Analysis Results: <span className="font-mono text-blue-600">{result.input}</span>
            </h2>
            <div className="flex items-center gap-4 text-sm text-gray-600">
              <div className="flex items-center">
                <span className="font-medium">IOC Type:</span>
                <span className="ml-1 px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-medium">
                  {result.type_description || result.type}
                </span>
              </div>
              {result.normalized_input && result.normalized_input !== result.input && (
                <div className="flex items-center">
                  <span className="font-medium">Normalized:</span>
                  <span className="ml-1 font-mono text-xs bg-gray-100 px-2 py-1 rounded">
                    {result.normalized_input}
                  </span>
                </div>
              )}
            </div>
          </div>
          <div className="flex gap-2">
            <span className={`px-3 py-1 rounded-full text-white text-xs font-medium ${getRiskBadgeColor(currentRisk)}`}>
              {currentRisk}
            </span>
            {result.metadata?.confidence_level && (
              <span className={`px-3 py-1 rounded-full text-white text-xs font-medium ${getConfidenceBadgeColor(result.metadata.confidence_level)}`}>
                {result.metadata.confidence_level} Confidence
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex flex-wrap gap-2 mb-4">
        {allTabs.map((key) => (
          <button
            key={key}
            title={formatKey(key)}
            className={`px-3 py-1 rounded flex items-center gap-1 text-sm transition-colors ${
              tab === key ? "bg-blue-600 text-white" : "bg-gray-200 hover:bg-gray-300"
            }`}
            onClick={() => setTab(key)}
          >
            <span>{tabIcons[key]}</span>
            <span className="capitalize">{key.replace('_', ' ')}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="min-h-[200px]">
        {renderContent()}
      </div>
    </div>
  );
};

export default ResultCard;