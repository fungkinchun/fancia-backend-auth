# Fancia — auth

Fancia's auth service provides OAuth2 / OpenID Connect support used by other Fancia services. It issues access and refresh tokens, validates tokens, exposes a JWKS endpoint, and provides a Swagger UI for the OpenAPI documentation.

This repository contains the auth service implementation and deployment artifacts used across the platform.

## Quick start

To run the service locally for development, build the project and provide the usual Spring configuration (for example via application.yml or environment variables). At minimum you need to provide a datasource, a keystore or JWK configuration, and any external service endpoints the auth service relies on (user lookup, client store, etc.).

## Endpoints and documentation

- [OpenAPI](http://fancia.co.uk/auth/swagger-ui/index.html) — use this to explore available endpoints and request/response schemas.
- Authorization endpoint (OIDC): /oauth2/authorize — used to initiate authorization code flows.
- Token endpoint: /oauth2/token — exchange authorization codes or credentials for tokens.
- Introspection endpoint: /oauth2/introspect — validate tokens from resource servers.
- JWKS endpoint: /.well-known/jwks.json — public keys for token signature verification.

## Create an OIDC client

Clients (applications) that authenticate via OAuth2/OIDC need to be registered. Please note: create a user first via [Create a user](http://fancia.co.uk/user/api/users). Depending on the auth store used in this deployment, client registration can be performed via an admin API or by adding configuration to the client store. Example curl request (replace host, token and values):

```bash
curl -X 'POST' \
'http://fancia.co.uk/auth/connect/register' \
-H 'accept: application/json' \
-H 'Authorization: Bearer <your-bearer-token>' \
-H 'Content-Type: application/json' \
-d '{
"client_name": "<your-client-name>"
"redirect_uris": ["<your-redirect-uri>"]
"grant_types": ["authorization_code", "refresh_token", "client_credentials"],
"response_types": ["code"],
"token_endpoint_auth_method": "client_secret_basic",
"post_logout_redirect_uris": ["<your-post-logout-redirect-uri>"]
"scope": "openid profile",
"require_authorization_consent": true
}'
```

The registration API typically responds with the created client metadata including `client_id` and, when applicable, a `client_secret`. Store client credentials securely (for example, in a secrets manager) and avoid committing them to source control. For development you can register a client with an in-memory store; for production, prefer a managed client store or a secure persisted backend.

## Configuration hints

- Keys and signing: configure JWKs or a keystore for signing tokens. Expose the public keys via the JWKS endpoint so resource servers can verify tokens.
- HTTPS and cookies: run the authorization endpoints behind HTTPS. Use secure cookie settings and appropriate SameSite policies when handling browser flows.
- Token lifetime and rotation: choose sensible access token TTLs and enable refresh tokens when long-lived sessions are required. Consider refresh token rotation and revocation support for security.
- Client credentials: store client secrets securely (for example using a secrets manager) and avoid committing secrets to source control.
