from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Dict, Any

from api.virustotal import check_virustotal
from api.abuseipdb import check_ip
from api.shodan_lookup import lookup_shodan
from api.otx_lookup import lookup_otx
from api.threatfox_lookup import lookup_threatfox
from api.urlhaus_lookup import lookup_urlhaus
from api.malwarebazaar_lookup import lookup_malwarebazaar
from api.ipinfo_lookup import lookup_ipinfo
from api.urlscan import lookup_urlscan
from api.utils import detect_input_type, extract_domain_from_url, resolve_domain, normalize_ioc, validate_ioc, get_ioc_description
from api.formatters import (
    format_virustotal, format_threatfox, format_abuseipdb, 
    format_shodan, format_otx, format_urlhaus, format_malwarebazaar, 
    format_ipinfo, format_urlscan
)
from llm.gpt_summary import SOCAnalystLLM, generate_summary

app = FastAPI(title="Unified Threat Analyzer", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SOC Analyst LLM
soc_analyst = SOCAnalystLLM()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "Unified Threat Analyzer"}

@app.post("/analyze")
async def analyze(request: Request):
    """Enhanced IOC analysis with comprehensive IOC type detection"""
    try:
        data = await request.json()
        input_value = data.get("input", "").strip()

        if not input_value:
            return JSONResponse(
                status_code=400, 
                content={"detail": "Must provide input value for analysis."}
            )

        # Detect IOC type
        detected_type = detect_input_type(input_value)
        
        # Validate IOC
        is_valid, error_message = validate_ioc(input_value, detected_type)
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content={
                    "detail": error_message,
                    "detected_type": detected_type,
                    "type_description": get_ioc_description(detected_type)
                }
            )
        
        # Normalize IOC for API processing
        normalized_value, final_type = normalize_ioc(input_value, detected_type)

        # Handle special case: ThreatFox query
        if final_type == "threatfox_query":
            tf_raw = lookup_threatfox(normalized_value)
            formatted_tf = format_threatfox(tf_raw)
            
            structured_data = {
                "input": input_value,
                "normalized_input": normalized_value,
                "type": final_type,
                "type_description": get_ioc_description(final_type),
                "threatfox": formatted_tf,
                "virustotal": {},
                "abuseipdb": {},
                "shodan": {},
                "otx": {},
                "urlhaus": {},
                "malwarebazaar": {},
                "ipinfo": {},
                "urlscan": {}
            }
            
            soc_analysis = soc_analyst.generate_soc_analysis(structured_data)
            
            return {
                "input": input_value,
                "normalized_input": normalized_value,
                "type": final_type,
                "type_description": get_ioc_description(final_type),
                "threatfox": formatted_tf,
                "soc_analysis": soc_analysis,
                "summary": soc_analysis["llm_analysis"]
            }

        # Handle unsupported IOC types
        unsupported_types = [
            "email", "cidr_ipv4", "cidr_ipv6", "registry_key", "file_path_windows", 
            "file_path_unix", "mutex", "user_agent", "bitcoin_address", "cve", 
            "asn", "yara_rule", "mac_address", "process_name", "port"
        ]
        
        if final_type in unsupported_types:
            return JSONResponse(
                status_code=400,
                content={
                    "detail": f"IOC type '{get_ioc_description(final_type)}' is not yet supported for threat intelligence analysis.",
                    "detected_type": final_type,
                    "type_description": get_ioc_description(final_type),
                    "supported_types": ["ip", "domain", "url", "hash", "threatfox_query"]
                }
            )

        # Convert URL to domain for analysis
        if final_type == "url":
            normalized_value = extract_domain_from_url(normalized_value)
            final_type = "domain"

        # Initialize results structure
        results = {
            "input": input_value,
            "normalized_input": normalized_value,
            "type": final_type,
            "type_description": get_ioc_description(final_type),
            "virustotal": {},
            "abuseipdb": {},
            "shodan": {},
            "otx": {},
            "threatfox": {},
            "urlhaus": {},
            "malwarebazaar": {},
            "ipinfo": {},
            "urlscan": {},
        }

        # ---- URLScan Active Scan ----
        urlscan_raw = lookup_urlscan(normalized_value)
        if urlscan_raw.get("method") == "active":
            results["urlscan"] = {
                "method": "active",
                "summary": urlscan_raw.get("summary", {}),
                "domain_info": urlscan_raw.get("domain_info", {}),
                "http": urlscan_raw.get("http", {}),
                "screenshot": urlscan_raw.get("screenshot"),
                "reportURL": urlscan_raw.get("reportURL")
            }
        else:
            results["urlscan"] = {"message": "URLScan active scan failed."}

        # ---- Main Threat Intelligence Lookups ----
        resolved_ip = None
        
        if final_type == "domain":
            resolved_ip = resolve_domain(normalized_value)
            if not resolved_ip:
                return JSONResponse(
                    status_code=400, 
                    content={"detail": f"Failed to resolve domain: {normalized_value}"}
                )
            
            # Execute all relevant lookups for domain
            results["abuseipdb"] = format_abuseipdb(check_ip(resolved_ip, normalized_value))
            results["ipinfo"] = format_ipinfo(lookup_ipinfo(resolved_ip, normalized_value))
            results["shodan"] = format_shodan(lookup_shodan(resolved_ip))
            results["otx"] = format_otx(lookup_otx(normalized_value, final_type))
            results["threatfox"] = format_threatfox(lookup_threatfox(normalized_value))
            results["virustotal"] = format_virustotal(check_virustotal(normalized_value))

        elif final_type == "ip":
            # Execute all relevant lookups for IP
            results["abuseipdb"] = format_abuseipdb(check_ip(normalized_value))
            results["shodan"] = format_shodan(lookup_shodan(normalized_value))
            results["ipinfo"] = format_ipinfo(lookup_ipinfo(normalized_value))
            results["otx"] = format_otx(lookup_otx(normalized_value, final_type))
            results["threatfox"] = format_threatfox(lookup_threatfox(normalized_value))
            results["virustotal"] = format_virustotal(check_virustotal(normalized_value))

        elif final_type == "hash":
            # Execute all relevant lookups for hash
            results["virustotal"] = format_virustotal(check_virustotal(normalized_value))
            results["otx"] = format_otx(lookup_otx(normalized_value, final_type))
            results["threatfox"] = format_threatfox(lookup_threatfox(normalized_value))
            results["urlhaus"] = format_urlhaus(lookup_urlhaus(normalized_value))
            results["malwarebazaar"] = format_malwarebazaar(lookup_malwarebazaar(normalized_value))

        else:
            return JSONResponse(
                status_code=400, 
                content={"detail": f"Unsupported IOC type for analysis: {final_type}"}
            )

        # ---- Raw Data Collection ----
        results["raw"] = {
            "virustotal": check_virustotal(normalized_value),
            "abuseipdb": check_ip(resolved_ip if resolved_ip else normalized_value),
            "shodan": lookup_shodan(resolved_ip if resolved_ip else normalized_value),
            "otx": lookup_otx(normalized_value, final_type),
            "threatfox": lookup_threatfox(normalized_value),
            "urlhaus": lookup_urlhaus(normalized_value),
            "malwarebazaar": lookup_malwarebazaar(normalized_value),
            "ipinfo": lookup_ipinfo(resolved_ip if resolved_ip else normalized_value),
            "urlscan": urlscan_raw,
        }

        # ---- Enhanced SOC Analysis ----
        soc_analysis = soc_analyst.generate_soc_analysis(results)
        
        # Add SOC analysis to results
        results["soc_analysis"] = soc_analysis
        
        # Backwards compatibility - keep the summary field
        results["summary"] = soc_analysis["llm_analysis"]
        
        # Add metadata for better tracking
        results["metadata"] = {
            "analyst_version": "2.0",
            "confidence_level": soc_analysis["confidence_level"],
            "risk_level": soc_analysis["risk_assessment"]["level"],
            "risk_score": soc_analysis["risk_assessment"]["score"],
            "recommended_actions": soc_analysis["recommended_actions"],
            "analysis_timestamp": soc_analysis["timestamp"]
        }

        return results

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "detail": f"Analysis failed: {str(e)}",
                "error_type": type(e).__name__
            }
        )

@app.post("/quick-analyze")
async def quick_analyze(request: Request):
    """Quick analysis endpoint for faster results (reduced API calls)"""
    try:
        data = await request.json()
        input_value = data.get("input", "").strip()
        
        if not input_value:
            return JSONResponse(
                status_code=400, 
                content={"detail": "Must provide input value."}
            )
        
        input_type = detect_input_type(input_value)
        
        # Only use core sources for quick analysis
        quick_results = {
            "input": input_value,
            "type": input_type,
            "virustotal": format_virustotal(check_virustotal(input_value)),
            "abuseipdb": check_ip(input_value) if input_type == "ip" else {},
            "threatfox": format_threatfox(lookup_threatfox(input_value))
        }
        
        # Quick SOC analysis with limited data
        soc_analysis = soc_analyst.generate_soc_analysis(quick_results)
        
        return {
            "input": input_value,
            "type": input_type,
            "quick_analysis": True,
            "soc_analysis": soc_analysis,
            "summary": soc_analysis["llm_analysis"]
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Quick analysis failed: {str(e)}"}
        )

@app.get("/sources")
async def get_sources():
    """Get information about available threat intelligence sources"""
    return {
        "sources": [
            {"name": "VirusTotal", "type": "Multi-engine malware scanner", "supported_iocs": ["ip", "domain", "hash", "url"]},
            {"name": "AbuseIPDB", "type": "IP reputation database", "supported_iocs": ["ip"]},
            {"name": "Shodan", "type": "Internet-connected device search", "supported_iocs": ["ip"]},
            {"name": "AlienVault OTX", "type": "Threat intelligence platform", "supported_iocs": ["ip", "domain", "hash"]},
            {"name": "ThreatFox", "type": "Malware IOC database", "supported_iocs": ["ip", "domain", "hash"]},
            {"name": "URLhaus", "type": "Malware URL database", "supported_iocs": ["hash", "url"]},
            {"name": "MalwareBazaar", "type": "Malware sample database", "supported_iocs": ["hash"]},
            {"name": "IPInfo", "type": "IP geolocation service", "supported_iocs": ["ip"]},
            {"name": "URLScan", "type": "URL analysis service", "supported_iocs": ["url", "domain"]}
        ],
        "analyst_capabilities": [
            "Risk assessment and scoring",
            "Multi-source correlation",
            "TTPs identification",
            "Threat attribution",
            "Actionable recommendations",
            "Confidence assessment"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)