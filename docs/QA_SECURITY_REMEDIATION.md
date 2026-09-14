# DBERT Internship Portal - QA & Security Remediation Log

| Phase | Category | Code | Description | Status | Verification |
|---|---|---|---|---|---|
| **Phase 1** | Security | `SEC-001` | Role escalation via password reset | ✅ FIXED | `test_intern_reset_creates_intern_session`, `test_company_reset_creates_company_session` |
| **Phase 1** | Security | `SEC-002` | Reset token returned in API response | ✅ FIXED | `test_forgot_password_never_returns_token_normal` |
| **Phase 1** | Security | `SEC-003` | Reset token logged to stdout | ✅ FIXED | `test_reset_token_not_in_stdout` |
| **Phase 1** | QA | `AUTH-001` | `test_auth.py` manually sets Flask session variables | ✅ FIXED | Extracted real auth path to `conftest.py` helpers. |
| **Phase 1** | QA | `AUTH-002` | `forgot-password` enumerates accounts via 404/200 diff | ✅ FIXED | Returns 200 identically for both paths. Verified by `test_forgot_password_neutral_for_unknown_email`. |
| **Phase 1** | QA | `AUTH-003` | Security checks coupled to `FLASK_DEBUG` / `app.debug` | ✅ FIXED | `app.debug` decoupled from `forgot-password` endpoint payload. |

## Phase 1 Implementation Notes

- **Database Changes**: Safely migrated `password_resets` table to explicitly store `account_type` and `account_id`, removing the brittle `email|intern` string encoding.
- **Test Infrastructure**: Created robust `conftest.py` helpers (`login_as_intern`, `login_as_company`) that use the real production auth mechanism instead of injecting session cookies manually. Added CSRF-exemption fixture specifically for tests.
