# Auth Requirements

## JWT

- Algorithm: **RS256** (RSA-PKCS1v15 + SHA-256)
- TTL: **≤ 300 s** — non-negotiable
- Scope: every API request, no exceptions
- Failure → **HTTP 401**

## Proof-of-Possession (PoP)

- Scheme: **EdDSA** signature over server-issued challenge
- Required: alongside JWT on every request
- Missing PoP → **HTTP 403 Forbidden**
- Implemented in [[crypto_layer]] via `ProofOfPossession(sk, challenge)`

## Identity Model

- `POST /auth/register` → stores `public_key`, returns `identity_id`
- Identity keys: EdDSA (for PoP) and RSA (for JWT validation)
- Key generation done client-side

## Zero-Trust Principle

- No implicit trust: stateless validation per request
- JWT + PoP are the **only** authentication mechanism; no sessions
- Links: [[security_rules#ES1]]

## Adversarial Tests

| ID | Attack | Expected Response |
|----|--------|-------------------|
| TS-03 | Replay expired JWT | HTTP 401 |
| TS-05 | Request without PoP | HTTP 403 |
