const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  buildAuthConfig,
  validateAuthConfig,
  validateGatewayToken,
  safeTokenEquals
} = require('../lib/gateway-auth');

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function createSignedJwt(payload, options) {
  const config = {
    secret: 'gateway-test-secret',
    alg: 'HS256',
    iat: Math.floor(Date.now() / 1000),
    ...options
  };

  const header = {
    alg: config.alg,
    typ: 'JWT'
  };
  const claimSet = {
    iat: config.iat,
    ...payload
  };

  const signingInput = [
    base64UrlEncode(JSON.stringify(header)),
    base64UrlEncode(JSON.stringify(claimSet))
  ].join('.');
  const sig = crypto
    .createHmac('sha256', config.secret)
    .update(signingInput)
    .digest('base64url');

  return {
    token: `${signingInput}.${sig}`,
    signingInput,
    signature: sig
  };
}

function nowSecondsPlus(offsetSeconds = 0) {
  return Math.floor(Date.now() / 1000) + offsetSeconds;
}

test('safeTokenEquals is constant-length aware', () => {
  assert.equal(safeTokenEquals('abc', 'abc'), true);
  assert.equal(safeTokenEquals('abc', 'abcd'), false);
  assert.equal(safeTokenEquals('abc', 'def'), false);
});

test('legacy mode validates only shared service token', () => {
  const authConfig = {
    legacyToken: 'legacy-secret',
    mode: 'legacy'
  };

  assert.deepEqual(validateGatewayToken('legacy-secret', authConfig), { ok: true, reason: null });
  assert.deepEqual(validateGatewayToken('wrong-secret', authConfig), { ok: false, reason: 'invalid_service_token' });
});

test('hybrid mode accepts legacy token and jwt token', () => {
  const authConfig = {
    legacyToken: 'legacy-secret',
    mode: 'hybrid',
    secret: 'jwt-secret',
    audienceList: ['gateway'],
    requireJwtClaims: false,
    clockSkewMs: 120000
  };

  const validJwt = createSignedJwt({
    aud: 'gateway',
    exp: nowSecondsPlus(600)
  }, {
    secret: 'jwt-secret'
  });

  assert.equal(validateGatewayToken('legacy-secret', authConfig).ok, true);
  assert.equal(validateGatewayToken(validJwt.token, authConfig).ok, true);
});

test('jwt mode rejects missing or legacy token', () => {
  const authConfig = {
    mode: 'jwt',
    secret: 'jwt-secret',
    audienceList: ['gateway'],
    requireJwtClaims: false,
    clockSkewMs: 120000
  };

  const validJwt = createSignedJwt({ aud: 'gateway', exp: nowSecondsPlus(600) }, { secret: 'jwt-secret' });

  assert.equal(validateGatewayToken(validJwt.token, authConfig).ok, true);
  assert.equal(validateGatewayToken('legacy-secret', authConfig).ok, false);
});

test('jwt rejects exp and nbf errors', () => {
  const authConfig = {
    mode: 'jwt',
    secret: 'jwt-secret',
    audienceList: ['gateway'],
    requireJwtClaims: false,
    clockSkewMs: 0
  };

  const now = Date.now;
  const fixedNowMs = Date.UTC(2026, 1, 1, 12, 0, 0);
  const fixedNowSec = Math.floor(fixedNowMs / 1000);
  Date.now = () => fixedNowMs;

  try {
    const expired = createSignedJwt({ aud: 'gateway', exp: fixedNowSec - 1 }, { secret: 'jwt-secret', alg: 'HS256', iat: fixedNowSec - 10 });
    const inactive = createSignedJwt({
      aud: 'gateway',
      nbf: fixedNowSec + 100,
      exp: fixedNowSec + 500,
      iat: fixedNowSec
    }, { secret: 'jwt-secret', alg: 'HS256' });

    assert.equal(validateGatewayToken(expired.token, authConfig).reason, 'token_expired');
    assert.equal(validateGatewayToken(inactive.token, authConfig).reason, 'token_not_active');
  } finally {
    Date.now = now;
  }
});

test('jwt validates issuer and audience', () => {
  const authConfig = {
    mode: 'jwt',
    secret: 'jwt-secret',
    audienceList: ['gateway'],
    issuer: 'https://issuer.test',
    requireJwtClaims: false,
    clockSkewMs: 0
  };

  const now = nowSecondsPlus(1000);
  const wrongAudience = createSignedJwt({
    aud: 'bad',
    exp: now + 600,
    iss: 'https://issuer.test',
    iat: now
  }, { secret: 'jwt-secret' });
  const wrongIssuer = createSignedJwt({ aud: 'gateway', exp: now + 600, iss: 'bad', iat: now }, { secret: 'jwt-secret' });
  const valid = createSignedJwt({
    aud: 'gateway',
    exp: now + 600,
    iss: 'https://issuer.test',
    iat: now
  }, { secret: 'jwt-secret' });

  assert.equal(validateGatewayToken(wrongAudience.token, authConfig).reason, 'invalid_audience');
  assert.equal(validateGatewayToken(wrongIssuer.token, authConfig).reason, 'invalid_issuer');
  assert.equal(validateGatewayToken(valid.token, authConfig).ok, true);
});

test('auth config validation enforces at least one mechanism', () => {
  assert.deepEqual(validateAuthConfig({ mode: 'legacy', legacyToken: '' }), {
    ok: false,
    reason: 'legacy_not_configured'
  });
  assert.deepEqual(validateAuthConfig({ mode: 'hybrid', legacyToken: '', secret: '' }), {
    ok: false,
    reason: 'auth_not_configured'
  });
  assert.deepEqual(validateAuthConfig({ mode: 'jwt', secret: '' }), {
    ok: false,
    reason: 'jwt_not_configured'
  });
  assert.equal(validateAuthConfig({ mode: 'legacy', legacyToken: 'ok' }).ok, true);
});

test('environment helper builds auth config defaults', () => {
  const originalMode = process.env.GATEWAY_AUTH_MODE;
  const originalAudience = process.env.GATEWAY_JWT_AUDIENCE;
  process.env.GATEWAY_AUTH_MODE = 'hybrid';
  process.env.GATEWAY_JWT_AUDIENCE = 'gateway,ai';

  try {
    const config = buildAuthConfig();
    assert.equal(config.mode, 'hybrid');
    assert.deepEqual(config.audienceList, ['gateway', 'ai']);
  } finally {
    process.env.GATEWAY_AUTH_MODE = originalMode;
    process.env.GATEWAY_JWT_AUDIENCE = originalAudience;
  }
});
