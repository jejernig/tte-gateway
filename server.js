'use strict';

const fastify = require('fastify')({ logger: true });
const pkg = require('./package.json');

const port = Number.parseInt(process.env.PORT || '3000', 10);
const host = process.env.HOST || '0.0.0.0';
const gitSha = process.env.GIT_SHA || process.env.COMMIT_SHA || 'unknown';
const version = process.env.APP_VERSION || pkg.version || 'unknown';
const classificationModel = process.env.CLASSIFICATION_MODEL || 'qwen2.5:3b-16k';
const ollamaUrl = (process.env.OLLAMA_URL || 'http://localhost:11434').replace(/\/$/, '');
const requestTimeoutMs = Number.parseInt(process.env.LLM_REQUEST_TIMEOUT_MS || '15000', 10);

fastify.get('/healthz', async () => ({ status: 'ok' }));
fastify.get('/readyz', async () => ({ status: 'ready' }));
fastify.get('/version', async () => ({ version, gitSha }));

function buildSchema(schema) {
  const docType = Array.isArray(schema && schema.doc_type) && schema.doc_type.length
    ? schema.doc_type
    : ['charter', 'standard', 'runbook', 'planning', 'postmortem', 'contract', 'research', 'misc'];
  const owningDivision = Array.isArray(schema && schema.owning_division) && schema.owning_division.length
    ? schema.owning_division
    : ['archives'];
  const sensitivity = Array.isArray(schema && schema.sensitivity) && schema.sensitivity.length
    ? schema.sensitivity
    : ['public-internal', 'restricted', 'sensitive'];

  return {
    type: 'object',
    additionalProperties: false,
    required: ['doc_type', 'owning_division', 'authoritative', 'sensitivity', 'subcategory', 'tags', 'confidence', 'rationale'],
    properties: {
      doc_type: { type: 'string', enum: docType },
      owning_division: { type: 'string', enum: owningDivision },
      authoritative: { type: 'boolean' },
      sensitivity: { type: 'string', enum: sensitivity },
      subcategory: { type: ['string', 'null'] },
      tags: { type: 'array', items: { type: 'string' } },
      confidence: { type: 'number' },
      rationale: { type: 'string' }
    }
  };
}

function parseJsonCandidate(value) {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim().replace(/^```json\s*/i, '').replace(/```$/i, '');
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function normalizeClassificationOutput(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const normalized = { ...raw };
  if (typeof normalized.confidence === 'number' && normalized.confidence >= 0 && normalized.confidence <= 1) {
    normalized.confidence = Math.round(normalized.confidence * 100);
  } else if (typeof normalized.confidence === 'string') {
    const parsed = Number.parseFloat(normalized.confidence);
    if (!Number.isNaN(parsed)) {
      normalized.confidence = parsed <= 1 ? Math.round(parsed * 100) : Math.round(parsed);
    }
  }
  if (normalized.subcategory === '') normalized.subcategory = null;
  if (Array.isArray(normalized.tags)) {
    normalized.tags = normalized.tags.map((tag) => String(tag).trim()).filter(Boolean);
  }
  return normalized;
}

function heuristicClassification(input, schema) {
  const docTypes = (schema && Array.isArray(schema.doc_type) && schema.doc_type.length)
    ? schema.doc_type
    : ['charter', 'standard', 'runbook', 'planning', 'postmortem', 'contract', 'research', 'misc'];
  const sensitivityLevels = (schema && Array.isArray(schema.sensitivity) && schema.sensitivity.length)
    ? schema.sensitivity
    : ['public-internal', 'restricted', 'sensitive'];
  const owningDivisions = (schema && Array.isArray(schema.owning_division) && schema.owning_division.length)
    ? schema.owning_division
    : [];

  const preview = [
    input.title,
    Array.isArray(input.headings) ? input.headings.join(' ') : '',
    input.preview,
    Array.isArray(input.keywords) ? input.keywords.join(' ') : ''
  ]
    .filter(Boolean)
    .join('\n')
    .toLowerCase();

  const pickDocType = () => {
    if (preview.includes('charter')) return 'charter';
    if (preview.includes('standard')) return 'standard';
    if (preview.includes('runbook')) return 'runbook';
    if (preview.includes('postmortem') || preview.includes('rca')) return 'postmortem';
    if (preview.includes('contract')) return 'contract';
    if (preview.includes('planning') || preview.includes('epic') || preview.includes('phase')) return 'planning';
    if (preview.includes('research')) return 'research';
    return 'misc';
  };

  const docType = docTypes.includes(pickDocType()) ? pickDocType() : 'misc';
  return {
    doc_type: docType,
    owning_division: owningDivisions.includes('archives') ? 'archives' : (owningDivisions[0] || null),
    authoritative: docType === 'charter' || docType === 'standard',
    sensitivity: sensitivityLevels.includes('restricted') ? 'restricted' : sensitivityLevels[0],
    subcategory: null,
    tags: [],
    confidence: 60,
    rationale: 'heuristic_fallback'
  };
}

fastify.post('/api/v1/llm/classify', async (request, reply) => {
  const { input, schema } = request.body || {};
  if (!input || typeof input !== 'object') {
    return reply.code(400).send({ error: 'input is required' });
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
  const schemaDefinition = buildSchema(schema);
  const prompt = [
    'You are a document classifier for Team Teddy Enterprises.',
    'Return a single JSON object that matches the schema exactly.',
    'Classify the document using the provided input fields.',
    '',
    'Input:',
    JSON.stringify(input, null, 2)
  ].join('\n');

  try {
    const response = await fetch(`${ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        model: classificationModel,
        prompt,
        stream: false,
        format: schemaDefinition,
        options: { temperature: 0.1 }
      })
    });
    if (!response.ok) {
      const fallback = heuristicClassification(input, schema);
      return reply.code(200).send({ classification: fallback, reason: 'ollama_error' });
    }
    const data = await response.json();
    const parsed = parseJsonCandidate(data.response);
    if (!parsed) {
      const fallback = heuristicClassification(input, schema);
      return reply.code(200).send({ classification: fallback, reason: 'invalid_json' });
    }
    const normalized = normalizeClassificationOutput(parsed) || parsed;
    return reply.code(200).send({ classification: normalized });
  } catch (err) {
    const fallback = heuristicClassification(input, schema);
    return reply.code(200).send({ classification: fallback, reason: 'ollama_unavailable' });
  } finally {
    clearTimeout(timeout);
  }
});

const start = async () => {
  try {
    await fastify.listen({ port, host });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
