import { useState } from 'react';
import AnalyzeForm from './AnalyzeForm';
import ResultCard from './ResultCard';

// IOC Compatibility Matrix Component (extracted from ResultCard)
const IOCCompatibilityMatrix = ({ showTitle = true }) => {
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

  return (
    <div className="space-y-6">
      {showTitle && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-blue-800 mb-2">
            📋 IOC Compatibility Matrix
          </h3>
          <p className="text-blue-700 text-sm">
            See which threat intelligence platforms support different IOC types. Enter an IOC above to begin analysis.
          </p>
        </div>
      )}

      {/* IOC Types Legend */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
        {Object.entries(iocTypes).map(([type, info]) => (
          <div key={type} className="border border-gray-200 rounded-lg p-3">
            <div className="flex items-center mb-2">
              <span className={`inline-block w-3 h-3 rounded-full mr-2 bg-${info.color}-500`}></span>
              <h4 className="font-medium text-gray-800 text-sm">{info.label}</h4>
            </div>
            <div className="text-xs text-gray-600 space-y-1">
              {info.examples.map((example, index) => (
                <div key={index} className="bg-gray-100 px-2 py-1 rounded font-mono text-xs">
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
                      <div className={`w-6 h-6 rounded-full mx-auto flex items-center justify-center ${
                        platform.supported.includes(iocType) ? "bg-green-200" : "bg-gray-200"
                      }`}>
                        {platform.supported.includes(iocType) ? (
                          <span className="text-xs text-green-800">✓</span>
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
            <div className="w-4 h-4 bg-green-200 rounded-full mr-2"></div>
            <span>Supports IOC type</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-gray-200 rounded-full mr-2"></div>
            <span>Does not support</span>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-lg p-6">
        <h4 className="font-semibold text-gray-800 mb-4 flex items-center">
          🚀 Enhanced Features
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
          <div className="flex items-start">
            <span className="text-blue-600 mr-2 text-lg">🧠</span>
            <div>
              <div className="font-medium text-gray-800">AI-Powered Analysis</div>
              <div className="text-gray-600">Claude Sonnet provides SOC analyst-level insights</div>
            </div>
          </div>
          <div className="flex items-start">
            <span className="text-green-600 mr-2 text-lg">⚡</span>
            <div>
              <div className="font-medium text-gray-800">Real-time Enrichment</div>
              <div className="text-gray-600">9 threat intelligence sources simultaneously</div>
            </div>
          </div>
          <div className="flex items-start">
            <span className="text-purple-600 mr-2 text-lg">🎯</span>
            <div>
              <div className="font-medium text-gray-800">Risk Scoring</div>
              <div className="text-gray-600">Automated risk assessment with confidence levels</div>
            </div>
          </div>
          <div className="flex items-start">
            <span className="text-orange-600 mr-2 text-lg">📊</span>
            <div>
              <div className="font-medium text-gray-800">Professional Reports</div>
              <div className="text-gray-600">Enterprise-grade threat intelligence reports</div>
            </div>
          </div>
          <div className="flex items-start">
            <span className="text-red-600 mr-2 text-lg">🔄</span>
            <div>
              <div className="font-medium text-gray-800">Multi-Format Support</div>
              <div className="text-gray-600">IPs, domains, URLs, hashes, and advanced queries</div>
            </div>
          </div>
          <div className="flex items-start">
            <span className="text-indigo-600 mr-2 text-lg">⚙️</span>
            <div>
              <div className="font-medium text-gray-800">Actionable Intelligence</div>
              <div className="text-gray-600">Clear recommendations for security teams</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async (input) => {
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      // Updated to use Vercel serverless function
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || 'Server error occurred.');
      }

      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error('Analysis error:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gray-50 p-6">
      <header className="text-center mb-6">
        <h1 className="text-3xl font-bold text-gray-800">
          🛡️ Unified Threat Analyzer
        </h1>
        <p className="text-gray-600 mt-1 text-sm">
          AI-powered threat intelligence analysis with 9 integrated sources
        </p>
        <div className="text-xs text-gray-500 mt-1">
          ⚡ Powered by Vercel Serverless & Claude Sonnet
        </div>
      </header>

      <AnalyzeForm onAnalyze={handleAnalyze} loading={loading} />

      {error && (
        <div className="text-center text-red-600 mt-4">
          ⚠️ {error}
        </div>
      )}

      {loading && (
        <div className="flex justify-center mt-6">
          <div className="flex items-center space-x-2">
            <svg className="animate-spin h-8 w-8 text-blue-600" viewBox="0 0 24 24">
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
                fill="none"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
              />
            </svg>
            <span className="text-blue-600 font-medium">Analyzing threat intelligence...</span>
          </div>
        </div>
      )}

      {result && !loading && (
        <section className="mt-6">
          <ResultCard result={result} />
        </section>
      )}

      {!result && !loading && !error && (
        <section className="mt-8">
          <IOCCompatibilityMatrix />
        </section>
      )}
    </main>
  );
}

export default App;