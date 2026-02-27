'use strict';

const fastify = require('fastify')({ logger: true });
const pkg = require('./package.json');

const port = Number.parseInt(process.env.PORT || '3000', 10);
const host = process.env.HOST || '0.0.0.0';
const gitSha = process.env.GIT_SHA || process.env.COMMIT_SHA || 'unknown';
const version = process.env.APP_VERSION || pkg.version || 'unknown';
const classificationModel = process.env.CLASSIFICATION_MODEL || 'qwen2.5:3b-16k';

fastify.get('/healthz', async () => ({ status: 'ok' }));
fastify.get('/readyz', async () => ({ status: 'ready' }));
fastify.get('/version', async () => ({ version, gitSha }));

fastify.post('/api/v1/llm/classify', async (request, reply) => {
  const { input, schema } = request.body || {};
  if (!input || typeof input !== 'object') {
    return reply.code(400).send({ error: 'input is required' });
  }
  const docTypes = (schema && Array.isArray(schema.doc_type) && schema.doc_type.length) ?
    schema.doc_type :
    ['charter', 'standard', 'runbook', 'planning', 'postmortem', 'contract', 'research', 'misc'];
  const sensitivityLevels = (schema && Array.isArray(schema.sensitivity) && schema.sensitivity.length) ?
    schema.sensitivity :
    ['public-internal', 'restricted', 'sensitive'];
  const owningDivisions = (schema && Array.isArray(schema.owning_division) && schema.owning_division.length) ?
    schema.owning_division :
    [];

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
  const classification = {
    doc_type: docType,
    owning_division: owningDivisions.includes('archives') ? 'archives' : (owningDivisions[0] || null),
    authoritative: docType === 'charter' || docType === 'standard',
    sensitivity: sensitivityLevels.includes('restricted') ? 'restricted' : sensitivityLevels[0],
    subcategory: null,
    tags: [],
    confidence: 92,
    rationale: `heuristic:${classificationModel}`
  };

  return reply.code(200).send({ classification });
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
