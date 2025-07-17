// utils/iocDetection.js
// Converted from api/utils.py

import dns from 'dns';
import { promisify } from 'util';

const resolveDns = promisify(dns.resolve4);

export function detectInputType(inputValue) {
  if (!inputValue || !inputValue.trim()) return 'unknown';
  
  const value = inputValue.trim();
  
  // ThreatFox advanced queries
  if (value.match(/^(ioc:|tag:|malware:|uuid:|threat_type:)/)) {
    return 'threatfox_query';
  }
  
  // Email addresses
  if (value.match(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
    return 'email';
  }
  
  // URLs (various protocols)
  if (value.match(/^(https?|ftp|ftps|sftp|file):\/\/[\w\.-]+(?:\/[\w\.-]*)*(?:\?[^\s]*)?(?:#[^\s]*)?$/)) {
    return 'url';
  }
  
  // URL without protocol
  if (value.match(/^[\w\.-]+\/[\w\.-\/]*(?:\?[^\s]*)?(?:#[^\s]*)?$/) && !value.match(/^[a-fA-F0-9]{32,}$/)) {
    return 'url_no_protocol';
  }
  
  // IPv4 addresses
  if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
    const parts = value.split('.');
    if (parts.every(part => parseInt(part) <= 255)) {
      return 'ipv4';
    }
  }
  
  // IPv6 addresses
  if (value.match(/^[a-fA-F0-9:]+$/) && value.includes(':') && value.length > 15) {
    return 'ipv6';
  }
  
  // CIDR notation
  if (value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)) {
    return 'cidr_ipv4';
  }
  
  if (value.match(/^[a-fA-F0-9:]+\/\d{1,3}$/)) {
    return 'cidr_ipv6';
  }
  
  // Hash types
  if (value.match(/^[a-fA-F0-9]{32}$/)) return 'md5';
  if (value.match(/^[a-fA-F0-9]{40}$/)) return 'sha1';
  if (value.match(/^[a-fA-F0-9]{56}$/)) return 'sha224';
  if (value.match(/^[a-fA-F0-9]{64}$/)) return 'sha256';
  if (value.match(/^[a-fA-F0-9]{96}$/)) return 'sha384';
  if (value.match(/^[a-fA-F0-9]{128}$/)) return 'sha512';
  if (value.match(/^[a-fA-F0-9]{70}$/)) return 'tlsh';
  if (value.match(/^[a-fA-F0-9]{72}$/)) return 'imphash';
  if (value.match(/^[a-zA-Z0-9+/]{27}=$/)) return 'ssdeep';
  
  // Registry keys
  if (value.match(/^HK(EY_)?(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\/i)) {
    return 'registry_key';
  }
  
  // File paths (Windows)
  if (value.match(/^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$/)) {
    return 'file_path_windows';
  }
  
  // File paths (Unix/Linux)
  if (value.match(/^\/(?:[^\/\0]+\/)*[^\/\0]*$/) && value.length > 1) {
    return 'file_path_unix';
  }
  
  // Mutex names
  if (value.match(/^(Global\\|Local\\)?[a-zA-Z0-9_\-\.{}]+$/) && value.length > 5) {
    if (['mutex', 'lock', 'sync', 'global\\', 'local\\'].some(pattern => 
      value.toLowerCase().includes(pattern))) {
      return 'mutex';
    }
  }
  
  // User-Agent strings
  if (value.match(/^Mozilla\/[\d\.]+ \(.*\).*$/) || value.includes('User-Agent:')) {
    return 'user_agent';
  }
  
  // Bitcoin addresses
  if (value.match(/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/) || value.match(/^bc1[a-z0-9]{39,59}$/)) {
    return 'bitcoin_address';
  }
  
  // CVE identifiers
  if (value.match(/^CVE-\d{4}-\d{4,}$/i)) {
    return 'cve';
  }
  
  // ASN
  if (value.match(/^AS\d+$/i)) {
    return 'asn';
  }
  
  // YARA rule names
  if (value.match(/^rule\s+\w+\s*\{/i)) {
    return 'yara_rule';
  }
  
  // MAC addresses
  if (value.match(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)) {
    return 'mac_address';
  }
  
  // Process names
  if (value.match(/^[a-zA-Z0-9_\-]+\.exe$/i)) {
    return 'process_name';
  }
  
  // Port numbers
  if (value.match(/^\d{1,5}$/) && parseInt(value) >= 1 && parseInt(value) <= 65535) {
    return 'port';
  }
  
  // Domains
  if (value.match(/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/)) {
    return 'domain';
  }
  
  // Subdomains or hostnames
  if (value.match(/^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/) && value.split('.').length >= 2) {
    return 'hostname';
  }
  
  return 'unknown';
}

export function normalizeIoc(inputValue, iocType) {
  const value = inputValue.trim();
  
  // Handle URL variations
  if (iocType === 'url_no_protocol') {
    return [value.startsWith('http') ? value : `http://${value}`, 'url'];
  }
  if (iocType === 'url') {
    return [value, 'url'];
  }
  
  // Convert specific hash types to generic 'hash'
  if (['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'tlsh', 'imphash', 'ssdeep'].includes(iocType)) {
    return [value.toLowerCase(), 'hash'];
  }
  
  // Convert IPv4/IPv6 to generic 'ip'
  if (['ipv4', 'ipv6'].includes(iocType)) {
    return [value, 'ip'];
  }
  
  // Extract domain from URL for domain-based analysis
  if (iocType === 'url') {
    const domain = extractDomainFromUrl(value);
    return [domain, 'domain'];
  }
  
  // Handle hostname as domain
  if (iocType === 'hostname') {
    return [value, 'domain'];
  }
  
  return [value, iocType];
}

export function extractDomainFromUrl(url) {
  try {
    if (!url.startsWith('http://') && !url.startsWith('https://') && 
        !url.startsWith('ftp://') && !url.startsWith('ftps://')) {
      url = 'http://' + url;
    }
    const urlObj = new URL(url);
    return urlObj.hostname || url;
  } catch (error) {
    // Fallback regex extraction
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9\-\.]+)/);
    return match ? match[1] : url;
  }
}

export async function resolveDomain(domain) {
  try {
    const addresses = await resolveDns(domain);
    return addresses[0] || null;
  } catch (error) {
    return null;
  }
}

export function validateIoc(inputValue, iocType) {
  const value = inputValue.trim();
  
  if (!value) {
    return [false, 'Empty input provided'];
  }
  
  if (iocType === 'unknown') {
    return [false, 'Unrecognized IOC type. Please check your input format.'];
  }
  
  // Additional validation for specific types
  if (['ipv4', 'ipv6'].includes(iocType)) {
    if (iocType === 'ipv4') {
      const parts = value.split('.');
      if (parts.length !== 4 || !parts.every(part => {
        const num = parseInt(part);
        return num >= 0 && num <= 255;
      })) {
        return [false, `Invalid ${iocType.toUpperCase()} address format`];
      }
    }
  }
  
  if (iocType === 'domain') {
    if (value.length > 253) {
      return [false, 'Domain name too long (max 253 characters)'];
    }
    if (value.includes('..')) {
      return [false, 'Invalid domain format (consecutive dots)'];
    }
  }
  
  if (iocType.startsWith('sha') || ['md5', 'tlsh'].includes(iocType)) {
    if (!value.match(/^[a-fA-F0-9]+$/)) {
      return [false, `Invalid ${iocType.toUpperCase()} hash format (must be hexadecimal)`];
    }
  }
  
  return [true, null];
}

export function getIocDescription(iocType) {
  const descriptions = {
    'threatfox_query': 'ThreatFox Advanced Query',
    'email': 'Email Address',
    'url': 'URL/Web Address',
    'ipv4': 'IPv4 Address',
    'ipv6': 'IPv6 Address',
    'cidr_ipv4': 'IPv4 CIDR Block',
    'cidr_ipv6': 'IPv6 CIDR Block',
    'md5': 'MD5 Hash',
    'sha1': 'SHA1 Hash',
    'sha224': 'SHA224 Hash',
    'sha256': 'SHA256 Hash',
    'sha384': 'SHA384 Hash',
    'sha512': 'SHA512 Hash',
    'tlsh': 'TLSH Hash',
    'imphash': 'Import Hash',
    'ssdeep': 'SSDeep Hash',
    'registry_key': 'Registry Key',
    'file_path_windows': 'Windows File Path',
    'file_path_unix': 'Unix/Linux File Path',
    'mutex': 'Mutex Name',
    'user_agent': 'User-Agent String',
    'bitcoin_address': 'Bitcoin Address',
    'cve': 'CVE Identifier',
    'asn': 'Autonomous System Number',
    'yara_rule': 'YARA Rule',
    'mac_address': 'MAC Address',
    'domain': 'Domain Name',
    'hostname': 'Hostname',
    'process_name': 'Process Name',
    'port': 'Port Number',
    'ip': 'IP Address',
    'hash': 'File Hash',
    'unknown': 'Unknown Type'
  };
  return descriptions[iocType] || 'Unknown Type';
}

export async function retryRequest(method, url, options = {}, retries = 2, delay = 2000) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, {
        method: method.toUpperCase(),
        ...options
      });
      return response;
    } catch (error) {
      if (attempt < retries) {
        const waitTime = delay * Math.pow(2, attempt); // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, waitTime));
      } else {
        throw error;
      }
    }
  }
}