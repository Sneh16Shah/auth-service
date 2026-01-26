WEEK 3 — AUTH SERVICE: HARDENING, CLEAN API, AND REFRESH TOKENS
==============================================================

What I Built
------------
- Standard JSON responses across endpoints (`message`, optional `token`, optional `refresh_token`)
- Strict HTTP method enforcement (reject wrong methods) and clean OPTIONS preflight handling
- Basic input validation (email normalization + format validation, password length checks)
- Hardened JWT validation (issuer validated, HS256-only allowed)
- Added access token + refresh token flow:
  - `/login` returns `token` + `refresh_token`
  - `/refresh` rotates refresh tokens and returns a new pair
  - `/protected` checks access token via `Authorization: Bearer <token>`
- Docker Compose now loads backend environment variables from `backend/.env`
- Basic HTTP server timeouts (read/write/idle) for safer production behavior under slow clients

What I Learned
--------------
- Why decoding client JSON directly into DB models is risky (clients can try to send `user_id` or timestamps)
- Why consistent JSON responses make clients simpler (no mixing plain text and JSON)
- How CORS preflight works and why OPTIONS should be handled explicitly
- Why access tokens should be short-lived and refresh tokens longer-lived
- Refresh token rotation pattern:
  - valid refresh token → mint new access + refresh token, invalidate the old refresh token
  - expired refresh token → deny and force login
- Why storing raw refresh tokens in the database is a bad idea
  - Instead store a one-way hash and compare/look up by hash
- Why `http.Server` timeouts matter (protects against slowloris-style connections)

Key Conceptual Learnings
------------------------
- Separation of concerns:
  - DB layer should persist and query data, not do auth logic or hashing
  - Handlers should validate input, call services/DB, and decide HTTP responses
- Refresh token handling should include:
  - Expiry check
  - Rotation (invalidate old token on refresh)
  - Cleanup when expired
- Secrets management:
  - Local dev: use `.env` + Compose `env_file` (and keep `.env` out of git)
  - Production: secrets should be injected by the platform/secret manager, not shipped in the repo or image

What Confused Me (And What I Understood Later)
----------------------------------------------
- Why my refresh request was failing even though I was sending `refresh_token`
  - Because the endpoint expects `{"refresh_token":"..."}` in the JSON body, not as a header
- Why “hashing refresh tokens with bcrypt” felt awkward
  - bcrypt includes a random salt, which makes “lookup by value” impossible without scanning rows
  - A deterministic hash lets the DB do fast lookups by the hashed value

What Broke (And Why)
--------------------
1. `400 Invalid request payload` on `/refresh`
   - Cause: sending `refresh_token` as a header instead of JSON body
   - Fix: send JSON body `{"refresh_token":"<token>"}`

2. Refresh token verification couldn’t be reliable
   - Cause: refresh token JWT needs its own secret, separate from access token secret
   - Fix: add `REFRESH_TOKEN_SECRET` and validate refresh tokens with it

Outcome
-------
- Safer and more predictable API behavior (methods enforced, JSON responses consistent)
- Auth flow supports short-lived access tokens with rotating refresh tokens
- Docker Compose setup is easier to run locally because the backend loads env vars automatically
