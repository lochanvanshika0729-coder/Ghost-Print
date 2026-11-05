const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

function loadLocalEnv() {
  const file = path.join(__dirname, '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || match[1] in process.env) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
}

loadLocalEnv();

function isLoopback(hostname) {
  const host = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host === '::1') return true;
  return net.isIP(host) === 4 && host.startsWith('127.');
}

function configuration() {
  const serviceUrl = (process.env.GHOSTGUARD_AI_URL || 'http://127.0.0.1:8001').replace(/\/+$/, '');
  try {
    const parsed = new URL(serviceUrl);
    if (!['http:', 'https:'].includes(parsed.protocol) || !isLoopback(parsed.hostname) || parsed.username || parsed.password) {
      return { enabled: false, provider: 'Ollama (local)', model: process.env.OLLAMA_MODEL || 'qwen3:1.7b',
        serviceUrl: '', message: 'The AI service URL must point to a loopback host.' };
    }
  } catch {
    return { enabled: false, provider: 'Ollama (local)', model: process.env.OLLAMA_MODEL || 'qwen3:1.7b',
      serviceUrl: '', message: 'The AI service URL is invalid.' };
  }
  return { enabled: true, provider: 'Ollama (local)', model: process.env.OLLAMA_MODEL || 'qwen3:1.7b', serviceUrl };
}

async function proxyAI(route, payload, method = 'POST') {
  const config = configuration();
  if (!config.enabled) throw new Error(config.message || 'Local AI service is disabled.');
  const safePath = String(route || '').replace(/^\/+/, '');
  if (!['ai/health', 'ai/retrieve-evidence', 'ai/analyze-evidence', 'ai/explain-case', 'ai/investigate'].includes(safePath)) {
    throw new Error('AI endpoint is not allowed.');
  }
  let response;
  try {
    response = await fetch(`${config.serviceUrl}/${safePath}`, {
      method,
      headers: payload === undefined ? {} : { 'Content-Type': 'application/json' },
      body: payload === undefined ? undefined : JSON.stringify(payload),
      signal: AbortSignal.timeout(95000)
    });
  } catch (error) {
    const reason = error?.name === 'TimeoutError' ? 'timed out' : 'is unavailable';
    throw new Error(`Local AI service ${reason}. Start it on 127.0.0.1:8001.`);
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error('Local AI service returned an invalid response.'); }
  return { status: response.status, body: data };
}

async function explainCase(caseResult, request) {
  const result = await proxyAI('ai/explain-case', {
    case_id: String(caseResult?.case_id || request?.case_id || ''),
    deterministic_case: caseResult || undefined
  });
  return result.body;
}

module.exports = { configuration, explainCase, isLoopback, proxyAI };
