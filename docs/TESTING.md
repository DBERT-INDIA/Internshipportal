# DBERT Internship Portal - Test Documentation

## Overview

The DBERT testing suite relies on PyTest. Tests are configured to run against in-memory/temporary SQLite databases to ensure perfect isolation and no side-effects on production data.

## Environment Variables during Tests

When tests run, `conftest.py` strictly forces the following environment variables to ensure production-like security posture without external side-effects:

```env
TESTING=true
FLASK_DEBUG=false
SMTP_PASS=""
```

## Running Tests

To run the full suite:

```bash
pytest tests/ -q --tb=short
```

To run a specific test file (e.g., the security tests):

```bash
pytest tests/security/test_phase1_auth.py -q --tb=short
```

## Fixtures & Test Data (`conftest.py`)

The test suite uses `conftest.py` to expose common fixtures.
The most important rule in writing tests: **TEST-001**.
Tests must NEVER manually mutate session variables (e.g. `session["role"] = "admin"`).
Tests MUST exercise the real authentication mechanisms.

Available helper functions:

- `app_client`: Injects a fresh Flask test client with a completely isolated SQLite DB.
- `seed_intern(db_path, email, password)`
- `seed_company(db_path, email, password)`
- `login_as_intern(client, db_path, email, password)` -> Returns session token
- `login_as_company(client, db_path, email, password)` -> Returns session token

## Test Suites

1. `tests/test_auth.py`: Basic route protection tests (legacy).
2. `tests/security/test_phase1_auth.py`: Complete coverage for Phase 1 password-reset and enumeration vulnerabilities (SEC-001, SEC-002, SEC-003, AUTH-002).
