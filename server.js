import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { promptShieldService } from './services/geminiService.js';
import { detectRegexPatterns } from './services/regexDetector.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Health & Status
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'PromptShield AI Security Gateway',
    version: '1.0.0',
    model: 'gemini-2.5-flash',
    promptApproach: 'Few-shot with Multi-Agent Tooling',
    temperature: 0.1,
    hasGeminiKey: promptShieldService.isConfigured()
  });
});

// Update API Key dynamically
app.post('/api/config/key', (req, res) => {
  const { apiKey } = req.body;
  if (apiKey) {
    promptShieldService.setApiKey(apiKey);
    return res.json({ success: true, hasGeminiKey: true, message: 'Gemini API key updated.' });
  }
  return res.status(400).json({ error: 'API key is required.' });
});

// 1. Semantic Detection Only
app.post('/api/scan', async (req, res) => {
  try {
    const { prompt, apiKey } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt text is required.' });
    }

    const findings = await promptShieldService.detectFindings(prompt, apiKey);
    res.json({
      findings,
      totalFindings: findings.length,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Scan endpoint error:', err);
    res.status(500).json({ error: err.message || 'Internal server error during scanning.' });
  }
});

// 2 & 3 & 5. Full Protection Pipeline (Scan, Risk Scoring, Rewriting, Intent Scoring, Telemetry)
app.post('/api/protect', async (req, res) => {
  try {
    const {
      prompt,
      transformationMode = 'redact',
      findingModes = {},
      policy = {},
      apiKey
    } = req.body;

    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt text is required.' });
    }

    const result = await promptShieldService.processPrompt({
      promptText: prompt,
      transformationMode,
      findingModes,
      customApiKey: apiKey,
      policy
    });

    res.json(result);
  } catch (err) {
    console.error('Protect endpoint error:', err);
    res.status(500).json({ error: err.message || 'Internal server error during prompt protection.' });
  }
});

// 4. File / Code Secret Scanner
app.post('/api/scan-file', async (req, res) => {
  try {
    const { filename = 'snippet.txt', content, apiKey } = req.body;
    if (!content || typeof content !== 'string') {
      return res.status(400).json({ error: 'File content string is required.' });
    }

    const findings = await promptShieldService.detectFindings(content, apiKey);

    // Group findings
    const secrets = findings.filter(f => f.category.includes('Secret') || f.type.includes('KEY') || f.type.includes('PASSWORD') || f.type.includes('DATABASE'));
    const pii = findings.filter(f => f.category.includes('PII') || f.type.includes('EMAIL') || f.type.includes('PHONE') || f.type.includes('PERSON'));
    const credentials = findings.filter(f => f.type.includes('PASSWORD') || f.type.includes('BEARER') || f.type.includes('DATABASE'));

    // Generate sanitized file content
    const sanitizedFindings = findings.map(f => ({
      ...f,
      replacementValue: `[REDACTED_${f.type}]`
    }));
    const sanitizedContent = promptShieldService.applyReplacements(content, sanitizedFindings);

    const riskScore = promptShieldService.calculateHeuristicRisk(findings);

    res.json({
      filename,
      findings,
      summary: {
        totalIssues: findings.length,
        secretsFound: secrets.length,
        piiRecords: pii.length,
        credentialsFound: credentials.length,
        riskScore,
        riskLevel: promptShieldService.getRiskLevel(riskScore),
        verdict: findings.length > 0 ? 'DO NOT SEND TO EXTERNAL AI' : 'CLEAN - SAFE TO TRANSMIT'
      },
      sanitizedContent,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('File scan endpoint error:', err);
    res.status(500).json({ error: err.message || 'Internal error scanning file.' });
  }
});

// Simulated Downstream LLM Provider Endpoint for Demo
app.post('/api/simulate-llm', (req, res) => {
  const { prompt } = req.body;
  const hasRawSecrets = detectRegexPatterns(prompt).length > 0;

  if (hasRawSecrets) {
    return res.json({
      status: 'BLOCKED_BY_PROXY',
      warning: 'RAW CREDENTIALS DETECTED IN PAYLOAD! The gateway intercepted this dangerous call before sending.',
      llmResponse: null
    });
  }

  // Simulated safe response demonstrating that intent was preserved
  return res.json({
    status: 'SUCCESS_200_OK',
    gatewaySafetyBadge: 'VERIFIED_CLEAN',
    llmResponse: `[Simulated Gemini / OpenAI Response]: Successfully processed your request! The code syntax has been debugged, API endpoints verified, and query executed safely without leaking any raw credentials or personal identity records.`
  });
});

app.listen(PORT, () => {
  console.log(`🛡️  PromptShield AI Security Gateway Backend listening on port ${PORT}`);
  console.log(`🔑  Gemini API Key configured: ${promptShieldService.isConfigured()}`);
});
