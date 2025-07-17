import { useState, useEffect } from 'react';

// IOC type detection logic (mirrors Python backend)
const detectIOCType = (input) => {
  if (!input || !input.trim()) return { type: 'unknown', description: 'Enter an IOC to analyze' };
  
  const value = input.trim();
  
  // ThreatFox advanced queries
  if (value.match(/^(ioc:|tag:|malware:|uuid:|threat_type:)/)) {
    return { type: 'threatfox_query', description: 'ThreatFox Advanced Query' };
  }
  
  // Email addresses
  if (value.match(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
    return { type: 'email', description: 'Email Address', supported: false };
  }
  
  // URLs
  if (value.match(/^(https?|ftp|ftps|sftp|file):\/\/[\w\.-]+/)) {
    return { type: 'url', description: 'URL/Web Address' };
  }
  
  // URL without protocol
  if (value.match(/^[\w\.-]+\/[\w\.-\/]/) && !value.match(/^[a-fA-F0-9]{32,}$/)) {
    return { type: 'url', description: 'URL/Web Address' };
  }
  
  // IPv4 addresses
  if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
    const parts = value.split('.');
    if (parts.every(part => parseInt(part) <= 255)) {
      return { type: 'ipv4', description: 'IPv4 Address' };
    }
  }
  
  // IPv6 addresses
  if (value.match(/^[a-fA-F0-9:]+$/) && value.includes(':') && value.length > 15) {
    return { type: 'ipv6', description: 'IPv6 Address' };
  }
  
  // CIDR notation
  if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)) {
    return { type: 'cidr_ipv4', description: 'IPv4 CIDR Block', supported: false };
  }
  
  if (value.match(/^[a-fA-F0-9:]+\/\d{1,3}$/)) {
    return { type: 'cidr_ipv6', description: 'IPv6 CIDR Block', supported: false };
  }
  
  // Hash types
  if (value.match(/^[a-fA-F0-9]{32}$/)) {
    return { type: 'md5', description: 'MD5 Hash' };
  }
  if (value.match(/^[a-fA-F0-9]{40}$/)) {
    return { type: 'sha1', description: 'SHA1 Hash' };
  }
  if (value.match(/^[a-fA-F0-9]{56}$/)) {
    return { type: 'sha224', description: 'SHA224 Hash' };
  }
  if (value.match(/^[a-fA-F0-9]{64}$/)) {
    return { type: 'sha256', description: 'SHA256 Hash' };
  }
  if (value.match(/^[a-fA-F0-9]{96}$/)) {
    return { type: 'sha384', description: 'SHA384 Hash' };
  }
  if (value.match(/^[a-fA-F0-9]{128}$/)) {
    return { type: 'sha512', description: 'SHA512 Hash' };
  }
  if (value.match(/^[a-fA-F0-9]{70}$/)) {
    return { type: 'tlsh', description: 'TLSH Hash' };
  }
  if (value.match(/^[a-zA-Z0-9+/]{27}=$/)) {
    return { type: 'ssdeep', description: 'SSDeep Hash' };
  }
  
  // Registry keys
  if (value.match(/^HK(EY_)?(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\/i)) {
    return { type: 'registry_key', description: 'Registry Key', supported: false };
  }
  
  // File paths
  if (value.match(/^[a-zA-Z]:\\/) || value.match(/^\/[^\/]/)) {
    return { type: 'file_path', description: 'File Path', supported: false };
  }
  
  // User-Agent strings
  if (value.match(/^Mozilla\/[\d\.]+ \(.*\)/)) {
    return { type: 'user_agent', description: 'User-Agent String', supported: false };
  }
  
  // Bitcoin addresses
  if (value.match(/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/) || value.match(/^bc1[a-z0-9]{39,59}$/)) {
    return { type: 'bitcoin_address', description: 'Bitcoin Address', supported: false };
  }
  
  // CVE identifiers
  if (value.match(/^CVE-\d{4}-\d{4,}$/i)) {
    return { type: 'cve', description: 'CVE Identifier', supported: false };
  }
  
  // ASN
  if (value.match(/^AS\d+$/i)) {
    return { type: 'asn', description: 'Autonomous System Number', supported: false };
  }
  
  // MAC addresses
  if (value.match(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)) {
    return { type: 'mac_address', description: 'MAC Address', supported: false };
  }
  
  // Process names
  if (value.match(/^[a-zA-Z0-9_\-]+\.exe$/i)) {
    return { type: 'process_name', description: 'Process Name', supported: false };
  }
  
  // Port numbers
  if (value.match(/^\d{1,5}$/) && parseInt(value) >= 1 && parseInt(value) <= 65535) {
    return { type: 'port', description: 'Port Number', supported: false };
  }
  
  // Domains
  if (value.match(/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/)) {
    return { type: 'domain', description: 'Domain Name' };
  }
  
  return { type: 'unknown', description: 'Unknown Type', supported: false };
};

const AnalyzeForm = ({ onAnalyze, loading }) => {
  const [input, setInput] = useState('');
  const [detectedIOC, setDetectedIOC] = useState({ type: 'unknown', description: 'Enter an IOC to analyze' });

  useEffect(() => {
    const iocInfo = detectIOCType(input);
    setDetectedIOC(iocInfo);
  }, [input]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!input.trim()) return;
    
    if (detectedIOC.supported === false) {
      alert(`IOC type "${detectedIOC.description}" is not yet supported for analysis.`);
      return;
    }
    
    onAnalyze(input.trim());
  };

  const getIOCBadgeColor = () => {
    if (detectedIOC.supported === false) return 'bg-red-100 text-red-800 border-red-200';
    if (detectedIOC.type === 'unknown') return 'bg-gray-100 text-gray-600 border-gray-200';
    return 'bg-green-100 text-green-800 border-green-200';
  };

  const examples = [
    { value: '8.8.8.8', type: 'IPv4 Address' },
    { value: 'google.com', type: 'Domain' },
    { value: 'https://example.com/malware', type: 'URL' },
    { value: 'd41d8cd98f00b204e9800998ecf8427e', type: 'MD5 Hash' },
    { value: 'malware:emotet', type: 'ThreatFox Query' },
  ];

  return (
    <div className="max-w-2xl mx-auto space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4" aria-label="Threat Intelligence Analyzer">
        {/* Input field with IOC detection */}
        <div className="relative">
          <input
            type="text"
            placeholder="Enter IP address, domain, URL, file hash, or ThreatFox query..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="w-full border border-gray-300 px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent text-sm"
            aria-label="Threat input"
          />
          
          {/* IOC Type Detection Badge */}
          {input && (
            <div className="absolute right-3 top-3">
              <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getIOCBadgeColor()}`}>
                {detectedIOC.description}
              </span>
            </div>
          )}
        </div>

        {/* Warning for unsupported IOC types */}
        {detectedIOC.supported === false && input && (
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800">
                  IOC Type Not Yet Supported
                </h3>
                <div className="mt-1 text-sm text-yellow-700">
                  <p>The detected IOC type "{detectedIOC.description}" is not currently supported for threat intelligence analysis.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Submit button */}
        <button
          type="submit"
          className={`w-full font-semibold py-3 px-4 rounded-lg transition duration-200 ${
            loading || detectedIOC.supported === false
              ? 'bg-gray-400 text-white cursor-not-allowed'
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
          disabled={loading || detectedIOC.supported === false}
          aria-busy={loading}
        >
          {loading ? (
            <span className="flex justify-center items-center space-x-2">
              <svg className="animate-spin h-5 w-5 text-white" viewBox="0 0 24 24">
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
              <span>Analyzing {detectedIOC.description}...</span>
            </span>
          ) : (
            `Analyze ${detectedIOC.type !== 'unknown' ? detectedIOC.description : 'IOC'}`
          )}
        </button>
      </form>

      {/* Example IOCs */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-700 mb-3">💡 Example IOCs to try:</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {examples.map((example, index) => (
            <button
              key={index}
              onClick={() => setInput(example.value)}
              className="text-left bg-white border border-gray-200 rounded px-3 py-2 hover:bg-blue-50 hover:border-blue-300 transition-colors"
            >
              <div className="font-mono text-sm text-blue-600">{example.value}</div>
              <div className="text-xs text-gray-500">{example.type}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Supported IOC Types */}
      <div className="bg-blue-50 rounded-lg p-4">
        <h3 className="text-sm font-medium text-blue-700 mb-2">🛡️ Supported IOC Types:</h3>
        <div className="text-xs text-blue-600 space-y-1">
          <div>• <strong>IP Addresses:</strong> IPv4, IPv6</div>
          <div>• <strong>Domains:</strong> example.com, subdomain.example.com</div>
          <div>• <strong>URLs:</strong> http://example.com/path, https://malicious.site</div>
          <div>• <strong>File Hashes:</strong> MD5, SHA1, SHA224, SHA256, SHA384, SHA512, TLSH</div>
          <div>• <strong>ThreatFox Queries:</strong> malware:emotet, tag:apt29, ioc:example.com</div>
        </div>
      </div>
    </div>
  );
};

export default AnalyzeForm;