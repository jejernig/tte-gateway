'use strict';

const fastify = require('fastify')({ logger: true });
const pkg = require('./package.json');

const port = Number.parseInt(process.env.PORT || '3000', 10);
const host = process.env.HOST || '0.0.0.0';
const gitSha = process.env.GIT_SHA || process.env.COMMIT_SHA || 'unknown';
const version = process.env.APP_VERSION || pkg.version || 'unknown';

fastify.get('/healthz', async () => ({ status: 'ok' }));
fastify.get('/readyz', async () => ({ status: 'ready' }));
fastify.get('/version', async () => ({ version, gitSha }));

const start = async () => {
  try {
    await fastify.listen({ port, host });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
