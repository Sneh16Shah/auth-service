WEEK 2 — AUTH SERVICE: USERS, JWT, AND DATABASE
===============================================

What I Built
------------
- `/register` — creates a new user in Postgres
- `/login` — verifies credentials and generates a JWT
- `/protected` — validates JWT in the Authorization header
- Added a Postgres service to Docker Compose and wired the app to it

What I Learned
--------------
- How to send JSON bodies with POST requests using Postman (Content-Type: application/json)
- Why Go handlers must read and validate request payloads (decode, check required fields)
- How to separate “user not found” (`sql.ErrNoRows`) from real DB errors
- Why JWT signing requires a secret from environment variables (never hardcode)
- How Docker networking works: use the Compose service name (`host=db`) instead of `localhost`
- Startup race conditions: the app may start before Postgres is ready; add retries/backoff

Key Conceptual Learnings
------------------------
- DB schema must match data types coming from code:
  - Don’t push huge `UnixNano()` integers into `SERIAL` (int4) columns
  - Let Postgres generate IDs (`SERIAL`/`BIGSERIAL`) and timestamps (`TIMESTAMP DEFAULT`)
- `EXPOSE 8080` documents intent; `ports: "8080:8080"` does the actual mapping
- Environment variables (e.g., `PORT`, `JWT_SECRET`) should be provided via Compose or platform secrets
- Handlers must never panic on nil dependencies; guard and respond with clear HTTP errors

What Confused Me (And What I Understood Later)
----------------------------------------------
- JWT flow: building claims vs. signing the token string
- `depends_on` does not wait for DB readiness; it only sets start order
- `Authorization: Bearer <token>` is required for protected endpoints; body is ignored

What Broke (And Why)
--------------------
1. “sql: unknown driver 'postgres'”  
   - Cause: missing driver import  
   - Fix: blank import `_ "github.com/lib/pq"`

2. “no such file or directory” when starting the container  
   - Cause: CMD pointed to a binary hidden by a bind mount or not built  
   - Fix: use `go run .` for dev containers; align build/run paths

3. “connection refused” to Postgres on startup  
   - Cause: DB not ready yet when app pings  
   - Fix: retry `NewDB()` with backoff; use `host=db` in connection string

4. 500 on `/register` (“Error checking user existence”)  
   - Cause: treating `sql.ErrNoRows` as an error  
   - Fix: return `(nil, nil)` for “not found” and handle conflict separately

Outcome
-------
- Backend and Postgres run together via Docker Compose
- `/register` creates users; `/login` authenticates; `/protected` validates JWTs
- Clear error handling replaces panics; logs make debugging straightforward
