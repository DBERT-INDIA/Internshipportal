import os
import tempfile
import pytest

os.environ["TESTING"] = "true"
os.environ.setdefault("FLASK_DEBUG", "false")
os.environ.setdefault("SMTP_PASS", "")

# Provide strong dummy values so app.py doesn't crash on production security guards during tests
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-for-ci-must-be-32c")
os.environ.setdefault("ADMIN_PASSWORD", "test_admin_strong_pass_123")
os.environ.setdefault("ADMIN_KEY", "test_admin_strong_key_123")
os.environ.setdefault("ADMIN_USERNAME", "test_admin")

from app import app as _app, init_db, get_db, set_password_hash, create_session, AUTH_COOKIE

@pytest.fixture(scope="function")
def app_client():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    _app.config["TESTING"] = True
    os.environ["DB_FILE"] = db_path
    
    # Disable CSRF globally during tests by adding everything to exempt list
    from app import CSRF_EXEMPT_ENDPOINTS
    CSRF_EXEMPT_ENDPOINTS.update(["intern_login", "company_login", "forgot_password", "reset_password", "check_email", "admin_reset_intern_password"])

    with _app.app_context():
        init_db()
        # Clear rate limits
        with get_db() as conn:
            conn.execute("DELETE FROM rate_events")
            conn.commit()

    with _app.test_client() as client:
        yield client, db_path
        
    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass


def seed_intern(db_path, email="intern@test.com", password="TestPass123", name="Test Intern"):
    os.environ["DB_FILE"] = db_path
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO intern_accounts "
            "(name, email, password_hash, password_set, is_active) VALUES (?,?,?,1,1)",
            (name, email, set_password_hash(password))
        )
        conn.commit()
        return conn.execute("SELECT id FROM intern_accounts WHERE email=?", (email,)).fetchone()["id"]


def seed_company(db_path, email="company@test.com", password="CompPass123", name="Test Corp"):
    os.environ["DB_FILE"] = db_path
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO companies "
            "(name, email, password_hash, is_active, is_approved) VALUES (?,?,?,1,1)",
            (name, email, set_password_hash(password))
        )
        conn.commit()
        return conn.execute("SELECT id FROM companies WHERE email=?", (email,)).fetchone()["id"]


def login_as_intern(client, db_path, email="intern@test.com", password="TestPass123", name="Test Intern"):
    seed_intern(db_path, email, password, name)
    resp = client.post("/intern/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"login_as_intern failed {resp.status_code}: {resp.data}"
    return resp


def login_as_company(client, db_path, email="company@test.com", password="CompPass123", name="Test Corp"):
    seed_company(db_path, email, password, name)
    resp = client.post("/company/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"login_as_company failed {resp.status_code}: {resp.data}"
    return resp


def get_latest_reset_token_hash(db_path, email, account_type="intern"):
    os.environ["DB_FILE"] = db_path
    with get_db() as conn:
        row = conn.execute(
            "SELECT token FROM password_resets "
            "WHERE email=? AND account_type=? AND used=0 ORDER BY id DESC LIMIT 1",
            (email, account_type)
        ).fetchone()
    return row["token"] if row else None


def inject_reset_token(db_path, email, account_type="intern"):
    import secrets, hashlib, datetime
    os.environ["DB_FILE"] = db_path
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    expires_at = (datetime.datetime.now() + datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        acct_id = None
        if account_type == "intern":
            row = conn.execute("SELECT id FROM intern_accounts WHERE email=? LIMIT 1", (email,)).fetchone()
        else:
            row = conn.execute("SELECT id FROM companies WHERE email=? LIMIT 1", (email,)).fetchone()
        if row:
            acct_id = row["id"]
        conn.execute("UPDATE password_resets SET used=1 WHERE email=? AND account_type=? AND used=0",
                     (email, account_type))
        conn.execute(
            "INSERT INTO password_resets (account_type, account_id, email, token, expires_at) VALUES (?,?,?,?,?)",
            (account_type, acct_id, email, token_hash, expires_at)
        )
        conn.commit()
    return raw
