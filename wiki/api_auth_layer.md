# API & Auth Layer

**Module:** `ztss-api/` + `ztss-tests/`  
**Owner:** Anas El Mahfoudy

## REST Endpoints

```
POST /auth/register    → { public_key, identity_id }
POST /auth/token       → JWT (TTL=300s, RS256)
POST /upload           → { root_cid, chunks_count }
GET  /download/:cid    → stream (ciphertext)
POST /share            → { re_key, delegated_cid }
GET  /audit            → [{ timestamp, action, sig }]
```

## JWT Specification

- Algorithm: **RS256** (RSA + SHA-256)
- TTL: **≤ 300 seconds (5 minutes)** — hard constraint
- Every request validated: JWT signature + Proof-of-Possession

## Middleware Requirements

- JWT RS256 validation on **every** request
- PoP (EdDSA signature over challenge) verified on **every** request
- `TF-06`: expired JWT → **HTTP 401**
- `TS-03`: replayed expired JWT → **HTTP 401**
- `TS-05`: missing PoP → **HTTP 403 Forbidden**

## Auth Service

- `POST /auth/register`: registers public key, returns `identity_id`
- `POST /auth/token`: issues 300s RS256 JWT

## Audit Log

- Every access generates a **signed, timestamped log entry**
- Format: `{ timestamp, action, sig }`
- Accessible via `GET /audit`
- Links to [[security_rules#ES5]]

## Framework

- `net/http` (stdlib) or **Fiber** — choice is implementation detail
- No other frameworks mandated

## Required Files

```
ztss-api/
  server.go      # routing, startup
  auth.go        # register, token, PoP verification
  middleware.go  # JWT RS256 + PoP middleware
  api_test.go    # unit + integration tests
```
