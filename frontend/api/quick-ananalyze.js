// api/quick-analyze.js
import { detectInputType, validateIoc, getIocDescription } from '../utils/iocDetection.js';
import { formatVirusTotal, formatThreatFox } from '../utils/formatters.js';
import { SOCAnalystLLM } from '../utils/claude.js';
import { 
  checkVirusTotal, 
  checkIP, 
  lookupThreatFox 
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
        detail: "Must provide input value."
      });
    }
    
    const inputType = detectInputType(inputValue);
    const [isValid, errorMessage] = validateIoc(inputValue, inputType);
    
    if (!isValid) {
      return res.status(400).json({
        detail: errorMessage,
        detected_type: inputType,
        type_description: getIocDescription(inputType)
      });
    }
    
    // Only use core sources for quick analysis
    const [vtResult, abuseResult, tfResult] = await Promise.allSettled([
      checkVirusTotal(inputValue),
      inputType === "ip" ? checkIP(inputValue) : Promise.resolve({}),
      lookupThreatFox(inputValue)
    ]);

    const quickResults = {
      input: inputValue,
      type: inputType,
      type_description: getIocDescription(inputType),
      virustotal: formatVirusTotal(vtResult.status === 'fulfilled' ? vtResult.value : { error: vtResult.reason?.message }),
      abuseipdb: abuseResult.status === 'fulfilled' ? abuseResult.value : {},
      threatfox: formatThreatFox(tfResult.status === 'fulfilled' ? tfResult.value : { error: tfResult.reason?.message })
    };
    
    // Quick SOC analysis with limited data
    const socAnalyst = new SOCAnalystLLM();
    const socAnalysis = await socAnalyst.generateSOCAnalysis(quickResults);
    
    return res.status(200).json({
      input: inputValue,
      type: inputType,
      type_description: getIocDescription(inputType),
      quick_analysis: true,
      soc_analysis: socAnalysis,
      summary: socAnalysis.llm_analysis,
      metadata: {
        analyst_version: "2.0-quick",
        confidence_level: socAnalysis.confidence_level,
        risk_level: socAnalysis.risk_assessment.level,
        risk_score: socAnalysis.risk_assessment.score,
        recommended_actions: socAnalysis.recommended_actions,
        analysis_timestamp: socAnalysis.timestamp
      }
    });
    
  } catch (error) {
    console.error('Quick analysis error:', error);
    return res.status(500).json({
      detail: `Quick analysis failed: ${error.message}`,
      error_type: error.constructor.name
    });
  }
}