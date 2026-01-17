WEEK 1 — AUTH SERVICE FOUNDATION
===============================

What I Built
------------
- A simple Go HTTP service
- Two endpoints:
  - `/`       → returns a welcome message
  - `/health` → returns healthy status
- The service is containerized using Docker
- The service is deployed publicly on Render

---

What I Learned
--------------
- How to build a minimal Go HTTP service
- How to expose HTTP endpoints in Go
- How Docker builds and runs a Go binary
- How a containerized service is deployed to production (Render)
- Difference between local development and production configuration

---

Key Conceptual Learnings
------------------------
- A backend service must explicitly listen on a port provided by the environment
- Production platforms (like Render) inject environment variables at runtime
- Docker Compose is primarily a *local development* tool
- `.env` files are NOT automatically loaded in production
- GitHub repositories should NOT commit `.env` files

---

What Confused Me (And What I Understood Later)
----------------------------------------------
- Initially, I assumed the `PORT` variable would be picked up from `.env`
- I learned that:
  - `.env` is not automatically loaded by Docker or Docker Compose
  - `.env` is ignored in production unless explicitly configured
- Render provides the `PORT` environment variable automatically
- For local development, `PORT` can be set via:
  - docker-compose.yml
  - or environment variables passed at runtime
- `.env` is useful only for local development, not production

---

What Broke (And Why)
--------------------
1. Running `docker-compose up -d` initially failed because:
   - The application was not correctly reading the `PORT` environment variable
   - The service was not listening on the port expected by the container

2. Using `CMD ["./app/auth-service"]` failed because:
   - The compiled binary did not exist at that path
   - The Docker build step had not placed the binary in the expected directory
   - This resulted in: "no such file or directory"

This taught me:
- Docker CMD paths must match the actual build output
- Containers fail immediately if the entry binary is missing
- Build-time and runtime paths must be aligned

---

Outcome
-------
- The service is live and reachable from the public internet
- `/health` confirms the service is running correctly
- I now understand how a backend service moves from code → container → production

Week 1 is complete.
