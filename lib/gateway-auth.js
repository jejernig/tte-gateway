const crypto = require('node:crypto');
const fs = require('node:fs');

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  const padding = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padding);
  return Buffer.from(padded, 'base64').toString('utf8');
}

function parseJwtPart(value) {
  try {
    return JSON.parse(decodeBase64Url(value));
  } catch {
    return null;
  }
}

function parseJwt(token) {
  const [headerRaw, payloadRaw, signatureRaw] = token.split('.');
  if (!headerRaw || !payloadRaw || !signatureRaw) return null;
  const header = parseJwtPart(headerRaw);
  const payload = parseJwtPart(payloadRaw);
  if (!header || !payload) return null;
  if (typeof header.alg !== 'string' || header.alg.trim().length === 0) return null;
  if (typeof signatureRaw !== 'string' || signatureRaw.length === 0) return null;
  return {
    header,
    payload,
    signature: signatureRaw,
    signingInput: `${headerRaw}.${payloadRaw}`
  };
}

function isJwtToken(token) {
  if (typeof token !== 'string') return false;
  return token.split('.').length === 3;
}

function normalizeSecret(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function safeTokenEquals(candidate, expected) {
  const left = normalizeSecret(candidate);
  const right = normalizeSecret(expected);
  if (!left || !right || left.length !== right.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
  } catch {
    return false;
  }
}

function normalizeConfig(value) {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : '';
}

function loadPublicKey(configuredKeyPathOrValue) {
  const value = normalizeConfig(configuredKeyPathOrValue);
  if (!value) return '';
  if (value.includes('\n') && value.includes('BEGIN PUBLIC KEY')) return value;
  if (value.startsWith('file://')) {
    const path = value.replace(/^file:\/\//, '');
    return fs.readFileSync(path, 'utf8');
  }
  if (/[\\\/]/.test(value) && fs.existsSync(value)) {
    return fs.readFileSync(value, 'utf8');
  }
  return value;
}

function buildAuthConfig() {
  const audience = normalizeConfig(process.env.GATEWAY_JWT_AUDIENCE);
  const issuer = normalizeConfig(process.env.GATEWAY_JWT_ISSUER);
  const secret = normalizeConfig(process.env.GATEWAY_JWT_SECRET);
  const publicKey = loadPublicKey(normalizeConfig(process.env.GATEWAY_JWT_PUBLIC_KEY));
  const configuredMode = normalizeConfig(process.env.GATEWAY_AUTH_MODE);
  const mode = configuredMode === 'legacy' || configuredMode === 'jwt' || configuredMode === 'hybrid'
    ? configuredMode
    : 'legacy';

  return {
    audience,
    audienceList: audience ? audience.split(',').map((value) => value.trim()).filter(Boolean) : [],
    issuer,
    secret,
    publicKey,
    requireJwtClaims: process.env.GATEWAY_AUTH_REQUIRE_JWT_CLAIMS === 'true',
    clockSkewMs: Number.parseInt(process.env.GATEWAY_JWT_CLOCK_SKEW_MS || '120000', 10) || 120000,
    mode
  };
}

function hasJwtConfig(config) {
  return Boolean(config.secret || config.publicKey);
}

function normalizeAuds(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((entry) => typeof entry === 'string' && entry.length > 0);
  return [];
}

function validateJwtClaims(payload, config) {
  const now = Date.now();
  const nowSeconds = Math.floor(now / 1000);
  const skewSeconds = Math.max(0, Math.floor(config.clockSkewMs / 1000));
  const exp = typeof payload.exp === 'number' ? payload.exp : null;
  const nbf = typeof payload.nbf === 'number' ? payload.nbf : null;
  const iat = typeof payload.iat === 'number' ? payload.iat : null;

  if (exp !== null && nowSeconds - skewSeconds > exp) return 'token_expired';
  if (nbf !== null && nowSeconds + skewSeconds < nbf) return 'token_not_active';
  if (config.requireJwtClaims && iat !== null && nowSeconds + skewSeconds < iat) return 'token_not_issued';

  if (config.issuer && payload.iss !== config.issuer) return 'invalid_issuer';

  if (config.audienceList.length > 0) {
    const tokenAudiences = normalizeAuds(payload.aud);
    const hasAudience = tokenAudiences.some((aud) => config.audienceList.includes(aud));
    if (!hasAudience) return 'invalid_audience';
  }

  return null;
}

function supportsSignatureAlgorithm(algorithm) {
  if (!algorithm) return false;
  return [
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
    'PS256',
    'PS384',
    'PS512'
  ].includes(algorithm);
}

function hmacAlgorithm(alg) {
  if (alg === 'HS256') return 'sha256';
  if (alg === 'HS384') return 'sha384';
  if (alg === 'HS512') return 'sha512';
  return '';
}

function rsaVerifyAlgorithm(alg) {
  if (alg === 'RS256' || alg === 'PS256') return 'RSA-SHA256';
  if (alg === 'RS384' || alg === 'PS384') return 'RSA-SHA384';
  if (alg === 'RS512' || alg === 'PS512') return 'RSA-SHA512';
  return '';
}

function verifyJwtSignature(parsed, config) {
  const alg = parsed.header.alg;
  if (!supportsSignatureAlgorithm(alg)) {
    return false;
  }

  if (alg.startsWith('HS')) {
    if (!config.secret) return false;
    const digest = crypto
      .createHmac(hmacAlgorithm(alg), config.secret)
      .update(parsed.signingInput)
      .digest('base64url');
    if (digest.length !== parsed.signature.length) return false;
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(parsed.signature));
  }

  if (!config.publicKey) return false;
  const verify = crypto.createVerify(rsaVerifyAlgorithm(alg));
  verify.update(parsed.signingInput);
  verify.end();
  return verify.verify(config.publicKey, parsed.signature, 'base64url');
}

function validateGatewayToken(token, config) {
  if (!token || typeof token !== 'string') {
    return { ok: false, reason: 'missing_token' };
  }

  const maybeJwt = isJwtToken(token);
  const mode = config.mode || 'legacy';
  const legacyToken = normalizeSecret(config.legacyToken);

  if (mode === 'legacy') {
    if (!legacyToken) {
      return { ok: false, reason: 'legacy_not_configured' };
    }
    const match = safeTokenEquals(token, legacyToken);
    return { ok: match, reason: match ? null : 'invalid_service_token' };
  }

  if (mode === 'jwt') {
    if (!hasJwtConfig(config)) {
      return { ok: false, reason: 'jwt_not_configured' };
    }
    if (!maybeJwt) {
      return { ok: false, reason: 'expected_jwt_token' };
    }
    return validateJwtToken(token, config);
  }

  if (mode === 'hybrid') {
    if (maybeJwt) {
      return validateJwtToken(token, config);
    }
    if (!legacyToken) {
      return hasJwtConfig(config)
        ? { ok: false, reason: 'expected_jwt_token' }
        : { ok: false, reason: 'invalid_service_token' };
    }
    const match = safeTokenEquals(token, legacyToken);
    return { ok: match, reason: match ? null : 'invalid_service_token' };
  }

  return { ok: false, reason: 'invalid_auth_mode' };
}

function validateJwtToken(token, config) {
  if (!hasJwtConfig(config)) {
    return { ok: false, reason: 'jwt_not_configured' };
  }
  const parsed = parseJwt(token);
  if (!parsed) {
    return { ok: false, reason: 'invalid_jwt' };
  }

  const claimFailure = validateJwtClaims(parsed.payload, config);
  if (claimFailure) {
    return { ok: false, reason: claimFailure };
  }

  if (!verifyJwtSignature(parsed, config)) {
    return { ok: false, reason: 'invalid_jwt_signature' };
  }
  return { ok: true, reason: null };
}

function describeAuthMode(config) {
  if (typeof config !== 'object' || config === null) {
    return 'legacy';
  }
  return config.mode || 'legacy';
}

function validateAuthConfig(config) {
  if (!config || typeof config !== 'object') {
    return { ok: false, reason: 'auth_config_invalid' };
  }
  const mode = describeAuthMode(config);
  const legacyToken = normalizeSecret(config.legacyToken);
  const hasJwt = hasJwtConfig(config);
  if (mode === 'legacy') {
    return legacyToken ? { ok: true, reason: null } : { ok: false, reason: 'legacy_not_configured' };
  }
  if (mode === 'jwt') {
    if (!hasJwt) return { ok: false, reason: 'jwt_not_configured' };
    return { ok: true, reason: null };
  }
  if (mode === 'hybrid') {
    if (!legacyToken && !hasJwt) {
      return { ok: false, reason: 'auth_not_configured' };
    }
    return { ok: true, reason: null };
  }
  return { ok: false, reason: 'invalid_auth_mode' };
}

module.exports = {
  buildAuthConfig,
  describeAuthMode,
  hasJwtConfig,
  isJwtToken,
  safeTokenEquals,
  validateAuthConfig,
  validateGatewayToken,
  validateJwtClaims,
  validateJwtToken
};
