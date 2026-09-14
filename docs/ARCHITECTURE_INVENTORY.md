# DBERT Internship Portal - Architecture & Trust Boundaries

## 1. Authentication Model (Phase 1 Baseline)

### Sessions
- **Implementation**: Custom token-based auth stored in `user_sessions` SQLite table.
- **Tokens**: 32-byte cryptographically random hex, indexed in DB.
- **Cookies**: 
  - `dbert_auth` (primary, HttpOnly, Lax, Secure-in-prod)
  - `dbert_session` (legacy fallback name, being deprecated)
- **Trust Model**: Server-authoritative. The browser holds an opaque pointer to the `user_sessions` row. All role enforcement (`require_role()`) evaluates the server-side row.

### Roles
- `intern`: Core user. Book mentor sessions, enroll in courses, submit tasks.
- `company`: Enterprise client. Post internships, approve/reject candidates.
- `mentor`: Staff role. Host 1-on-1 sessions.
- `admin`: Superuser. Accesses CSV imports, billing, user resets.

## 2. Password Reset Flow (Remediated)
- Token generated via `secrets.token_urlsafe(32)`.
- **Hashed in DB**: `hashlib.sha256()` of token stored; raw token never stored.
- **Role Separation**: `password_resets` table uses explicit `account_type` and `account_id` columns to properly resolve which table (`intern_accounts` vs `companies`) to update upon reset.

## 3. Upload Security
- Strict allowlist: `{"png", "jpg", "jpeg", "pdf"}`
- Magic byte validation (`sniff_upload_type()`) enforces real format independent of extension.
- 6MB global `MAX_CONTENT_LENGTH`.

## 4. Databases
- Primary SQLite (`dbert_internship.db`): Contains all users, enrollments, courses, sessions.
- SQLite `rate_events`: Shared across Gunicorn workers.

## 5. Trust Boundaries
1. **Unauthenticated Internet** → Flask application. Mitigated by `rate_check()` before core logic.
2. **Authenticated Users** → Protected routes via `get_current_user()` and role checks.
3. **Admin Actions** → Protected by `require_admin()` using the `user_sessions` table.
4. **Third Party (Gemini API)** → Fails safely to fallback responses on timeout/error.
