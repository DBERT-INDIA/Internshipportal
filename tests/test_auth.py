"""
P1-8: Authorization Regression Matrix
Automated test suite to guarantee role-based access control (RBAC) integrity.
"""
import os
import tempfile
import pytest

# Configure environment for testing before importing app
os.environ["FLASK_DEBUG"] = "true"
os.environ["TESTING"] = "true"
import tempfile
_temp_db_fd, _temp_db_path = tempfile.mkstemp()
os.environ["DB_FILE"] = _temp_db_path

from app import app, init_db, get_db

@pytest.fixture
def client():
    # Use a temporary database for tests
    db_fd, db_path = tempfile.mkstemp()
    app.config["TESTING"] = True
    app.config["DATABASE"] = db_path
    
    # Initialize test DB
    with app.app_context():
        init_db()
        # Clear any existing data first
        with get_db() as conn:
            conn.execute("DELETE FROM intern_accounts")
            conn.commit()
            
        # Seed test users
        with get_db() as conn:
            conn.execute("INSERT INTO intern_accounts (name, email, password_set, is_active) VALUES ('Intern', 'intern@example.com', 1, 1)")
            conn.commit()

    with app.test_client() as client:
        yield client

    os.close(db_fd)
    os.unlink(db_path)

def test_public_routes_accessible(client):
    """Ensure public pages don't require auth."""
    resp = client.get("/")
    assert resp.status_code == 200

def test_admin_routes_protected(client):
    """Ensure admin APIs reject unauthenticated requests."""
    resp = client.get("/admin/csv/enrollments")
    # Our app often returns 401 for unauthorized API calls
    assert resp.status_code in (401, 403, 302)

def test_intern_routes_protected(client):
    """Ensure intern APIs reject unauthenticated requests."""
    resp = client.get("/intern/my-applications")
    assert resp.status_code in (401, 403, 302)

def test_admin_route_intern_block(client):
    """Ensure a logged-in intern cannot access admin routes."""
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "intern"
        sess["email"] = "intern@example.com"
        
    resp = client.get("/admin/csv/enrollments")
    assert resp.status_code in (401, 403)
