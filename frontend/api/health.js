// api/health.js
export default async function handler(req, res) {
    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    return res.status(200).json({
      status: "healthy",
      service: "Unified Threat Analyzer",
      timestamp: new Date().toISOString(),
      version: "2.0"
    });
  }
  