# Database Scale-Out Strategy: PostgreSQL & Redis

**Objective:** Migrate from single-node SQLite + In-Memory Caching to a multi-node PostgreSQL + Redis architecture to achieve high availability, scale horizontally, and separate state from compute.

## Current State Architecture Limits
*   **SQLite constraints:** `app.py` uses WAL mode with an 8000ms timeout. This is robust for a single node, but completely prevents horizontal scaling. If you deploy a second app container behind a load balancer, they will have split-brain databases.
*   **In-Memory limits:** OTP rate limits (`_failed_logins`, `_otp_rate_limits`), active CSRF nonces, and `user_sessions` heavily rely on either memory or SQLite table locks.
*   **Cron Jobs:** Scheduled tasks are triggered via loopback HTTP (`/cron/`). With multiple servers, crons will fire `N` times unless locked.

## Phase 1: Redis for Ephemeral State (Zero Downtime)
Before touching the relational data, move all ephemeral data out of the app's memory to Redis.
1.  **Stand up Redis/Valkey cluster** (e.g., ElastiCache or self-hosted).
2.  **Migrate Rate Limiting:** Replace the sliding window `_failed_logins` dictionary in `app.py` with Redis `INCR` and `EXPIRE`.
3.  **Migrate User Sessions:** Move `user_sessions` to Redis. Use `SETEX session_token 86400 "{user_id, email, role}"`.
4.  **Cron Locks:** Implement a Redis Distributed Lock (Redlock) inside the `@app.route("/cron/*")` endpoints to ensure only one server executes the cron job.

## Phase 2: Refactoring `app.py` DB Abstraction
1.  **Extract `get_db()`:** Modify `get_db()` to return a standard Python DB-API 2.0 connection.
2.  **Abstract SQLiteisms:** 
    *   Change `INSERT OR IGNORE` to standard `INSERT ... ON CONFLICT DO NOTHING`.
    *   Replace `?` placeholders with `%s` (or use a library like `psycopg2` or `SQLAlchemy` Core).
    *   Rewrite `.fetchone()["column"]` accesses to a standard `DictCursor`.

## Phase 3: The PostgreSQL Migration (Scheduled Maintenance)
1.  **Deploy PostgreSQL Cluster** (e.g., RDS or Aurora).
2.  **Schema Translation:** Export the SQLite schema and translate it to PostgreSQL `CREATE TABLE` scripts (e.g., `INTEGER PRIMARY KEY AUTOINCREMENT` -> `SERIAL PRIMARY KEY`).
3.  **Data Extraction:**
    *   Bring the application down for maintenance.
    *   Use `pgloader` or a custom Python script to extract data from `internship.db` and insert it into PostgreSQL.
4.  **App Reconfiguration:** Point `app.py` via `DATABASE_URL` to PostgreSQL.
5.  **Restart & Verify:** Start the application cluster and verify read/write stability.

## Phase 4: Horizontal Scaling
With state completely decoupled into PostgreSQL and Redis:
1.  Containerize the application (Docker).
2.  Deploy multiple instances behind an Application Load Balancer.
3.  Turn off sticky sessions.
