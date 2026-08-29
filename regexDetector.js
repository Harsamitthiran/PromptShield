/**
 * Regex-based Pattern Detector for Sensitive Credentials, Tokens, Emails & PII
 */

export function detectRegexPatterns(text) {
  if (!text || typeof text !== 'string') return [];

  const findings = [];
  let idCounter = 1;

  const patterns = [
    {
      type: 'API_KEY',
      category: 'Secret / Credential',
      regex: /\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,}|sk-ant-[a-zA-Z0-9_-]{20,}|AIza[0-9A-Za-z-_]{35}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z-]{10,48}|AKIA[0-9A-Z]{16})\b/gi,
      severity: 'CRITICAL',
      confidence: 0.98,
      description: 'Live cloud/service provider API key or secret token detected.'
    },
    {
      type: 'GENERIC_SECRET_KEY',
      category: 'Secret / Credential',
      regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[\s:=]+["']?([a-zA-Z0-9_\-.~!@#$%^&*]{8,64})["']?/gi,
      severity: 'CRITICAL',
      confidence: 0.92,
      description: 'API key or authentication secret token assignment detected.',
      extractGroup: 1
    },
    {
      type: 'OBFUSCATED_SECRET',
      category: 'Secret / Credential',
      regex: /\b(s\s*k\s*-\s*[a-zA-Z0-9\s_-]{15,})\b/gi,
      severity: 'HIGH',
      confidence: 0.90,
      description: 'Adversarially obfuscated / spaced-out API token detected.'
    },
    {
      type: 'PASSWORD',
      category: 'Secret / Credential',
      regex: /(?:password|passwd|pwd|db_pass|admin_pass|secret)[\s:=]+["']?([^\s"'`]{4,40})["']?/gi,
      severity: 'CRITICAL',
      confidence: 0.94,
      description: 'Cleartext password or database credential string.',
      extractGroup: 1
    },
    {
      type: 'DATABASE_CONNECTION_STRING',
      category: 'Secret / Credential',
      regex: /\b(?:postgresql|postgres|mongodb(?:\+srv)?|mysql|redis|mssql):\/\/(?:[^:@\s]+:[^:@\s]+@)[^\s"']+/gi,
      severity: 'CRITICAL',
      confidence: 0.99,
      description: 'Live database connection URI with embedded user/password credentials.'
    },
    {
      type: 'BEARER_TOKEN',
      category: 'Secret / Credential',
      regex: /\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b/gi,
      severity: 'CRITICAL',
      confidence: 0.95,
      description: 'Authorization Bearer JWT or access token.',
      extractGroup: 1
    },
    {
      type: 'EMAIL',
      category: 'PII / Contact Info',
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,
      severity: 'MEDIUM',
      confidence: 0.96,
      description: 'Personal or corporate email address.'
    },
    {
      type: 'PHONE_NUMBER',
      category: 'PII / Contact Info',
      regex: /(?:\+?(\d{1,3}))?[-.\s]?(?:\(?(\d{2,4})\)?)[-.\s]?(\d{3,4})[-.\s]?(\d{3,4})/g,
      severity: 'MEDIUM',
      confidence: 0.88,
      description: 'Personal or business phone number.'
    },
    {
      type: 'CREDIT_CARD',
      category: 'Financial PII',
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
      severity: 'CRITICAL',
      confidence: 0.95,
      description: 'Payment card / credit card number.'
    },
    {
      type: 'SSN_NATIONAL_ID',
      category: 'Government PII',
      regex: /\b\d{3}-\d{2}-\d{4}\b/g,
      severity: 'CRITICAL',
      confidence: 0.97,
      description: 'Social Security Number (SSN) / National Identification number.'
    },
    {
      type: 'IP_ADDRESS',
      category: 'Infrastructure / Network',
      regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
      severity: 'LOW',
      confidence: 0.85,
      description: 'Internal or public IPv4 network address.'
    }
  ];

  for (const p of patterns) {
    let match;
    p.regex.lastIndex = 0;
    while ((match = p.regex.exec(text)) !== null) {
      const fullMatch = match[0];
      const targetValue = p.extractGroup !== undefined && match[p.extractGroup] ? match[p.extractGroup] : fullMatch;
      
      const startIndex = p.extractGroup !== undefined && match[p.extractGroup]
        ? match.index + fullMatch.indexOf(targetValue)
        : match.index;
      const endIndex = startIndex + targetValue.length;

      // Avoid duplicate or overlapping ranges
      const alreadyCaptured = findings.some(
        f => (startIndex >= f.startIndex && startIndex < f.endIndex) ||
             (endIndex > f.startIndex && endIndex <= f.endIndex)
      );

      if (!alreadyCaptured && targetValue.trim().length > 0) {
        findings.push({
          id: `regex_${idCounter++}`,
          type: p.type,
          category: p.category,
          value: targetValue,
          startIndex,
          endIndex,
          confidence: p.confidence,
          severity: p.severity,
          source: 'regex',
          description: p.description
        });
      }
    }
  }

  return findings.sort((a, b) => a.startIndex - b.startIndex);
}
