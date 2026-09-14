# DBERT Internship Portal - QA & Security Remediation Log

| Phase | Category | Code | Description | Status | Verification |
|---|---|---|---|---|---|
| **Phase 1** | Security | `SEC-001` | Role escalation via password reset | ✅ FIXED | `test_intern_reset_creates_intern_session`, `test_company_reset_creates_company_session` |
| **Phase 1** | Security | `SEC-002` | Reset token returned in API response | ✅ FIXED | `test_forgot_password_never_returns_token_normal` |
| **Phase 1** | Security | `SEC-003` | Reset token logged to stdout | ✅ FIXED | `test_reset_token_not_in_stdout` |
| **Phase 1** | QA | `AUTH-001` | `test_auth.py` manually sets Flask session variables | ✅ FIXED | Extracted real auth path to `conftest.py` helpers. |
| **Phase 1** | QA | `AUTH-002` | `forgot-password` enumerates accounts via 404/200 diff | ✅ FIXED | Returns 200 identically for both paths. Verified by `test_forgot_password_neutral_for_unknown_email`. |
| **Phase 1** | QA | `AUTH-003` | Security checks coupled to `FLASK_DEBUG` / `app.debug` | ✅ FIXED | `app.debug` decoupled from `forgot-password` endpoint payload. |
| **Phase 2** | DB Integrity | `PAY-001` | Non-atomic check-then-act for mentor bookings | ✅ FIXED | `test_pay001_mentor_slot_atomic_booking` |
| **Phase 2** | DB Integrity | `PAY-002` | Non-atomic `COUNT(*)` for cohort enrollment capacity | ✅ FIXED | `test_pay002_cohort_capacity_atomic_enrollment` |
| **Phase 2** | DB Integrity | `DATA-001` | Duplicate state transitions (e.g. double-approving projects) | ✅ FIXED | `test_data001_project_submission_atomic_review` |
| **Phase 3** | QA | `TEST-001` | Legacy tests mocking RBAC rather than testing it | ✅ FIXED | `test_phase3_authorization.py` matrix |
| **Phase 3** | Security | `ADMIN-001` | `require_admin()` privilege escalation allowed any staff to be admin | ✅ FIXED | `test_mentor_vertical_escalation_blocked` |

## Phase 1 Implementation Notes
- **Database Changes**: Safely migrated `password_resets` table to explicitly store `account_type` and `account_id`, removing the brittle `email|intern` string encoding.
- **Test Infrastructure**: Created robust `conftest.py` helpers (`login_as_intern`, `login_as_company`) that use the real production auth mechanism instead of injecting session cookies manually. Added CSRF-exemption fixture specifically for tests.

## Phase 2 Implementation Notes
- **Concurrency Defenses**: Migrated mentor slot booking (`intern_book_slot`), cohort seat allocation (`cohort_enroll`), and administrative state machines (`staff_project_decision`, `staff_review_task`, `mentor_update_status`, `admin_update_application_status`, `admin_update_enrollment_status`) to strictly atomic `UPDATE ... AND status = ?` queries, checking `rowcount` to prevent double-execution.

## Phase 3 Implementation Notes
- **RBAC Matrix**: Created dynamic `seed_staff` fixtures and tested access across Intern, Company, Mentor, and Admin roles to ensure horizontal and vertical boundaries are unbroken.
- **Privilege Escalation Fixed**: Addressed a critical flaw in `require_admin()` which previously granted root admin privileges to any authenticated back-office staff member via the `session.get("staff_id")` fallback.
