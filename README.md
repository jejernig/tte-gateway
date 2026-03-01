# tte-gateway

## Authentication

`tte-gateway` supports three auth modes for protected routes:

- `legacy` (default): requires `GATEWAY_API_TOKEN` in `Authorization: Bearer ...` or `x-gateway-token`/`x-service-token`.
- `jwt`: requires a valid JWT. Configure `GATEWAY_JWT_SECRET` (HS*) or `GATEWAY_JWT_PUBLIC_KEY` (RS/PS) and, optionally,:
  - `GATEWAY_JWT_AUDIENCE`
  - `GATEWAY_JWT_ISSUER`
  - `GATEWAY_JWT_CLOCK_SKEW_MS`
  - `GATEWAY_AUTH_REQUIRE_JWT_CLAIMS=true` to enforce `iat` checks.
- `hybrid`: accepts either valid legacy token or valid JWT. Use this during mixed deployments.

Set mode with `GATEWAY_AUTH_MODE`:

- `legacy`
- `jwt`
- `hybrid`

When auth is misconfigured and a required secret/key is missing, startup route checks return `503` with authentication configuration error payloads.

## Development

- Install dependencies: `npm install`
- Run tests: `npm test`
