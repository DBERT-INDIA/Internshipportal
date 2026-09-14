"""
Phase 4 Security Regression Suite - CSRF
Covers: CSRF token enforcement for state-changing endpoints
"""
import pytest
from tests.conftest import login_as_intern

def test_csrf_missing_token_rejected(app_client):
    client, db_path = app_client
    
    # Login sets up the auth cookie
    login_as_intern(client, db_path)
    
    # Attempt to update profile without CSRF token
    resp = client.post("/intern/update-profile", json={"name": "New Name"})
    assert resp.status_code == 403
    assert b"Invalid or missing CSRF token" in resp.data

def test_csrf_invalid_token_rejected(app_client):
    client, db_path = app_client
    login_as_intern(client, db_path)
    
    # Attempt to update profile with GARBAGE CSRF token
    resp = client.post(
        "/intern/update-profile", 
        json={"name": "New Name"}, 
        headers={"X-CSRF-Token": "garbage_token_12345"}
    )
    assert resp.status_code == 403
    assert b"Invalid or missing CSRF token" in resp.data

def test_csrf_valid_token_accepted(app_client):
    client, db_path = app_client
    login_as_intern(client, db_path)
    
    # To get a valid CSRF token, we can just load the portal page 
    # which renders the CSRF token in the HTML, or access the session directly.
    with client.session_transaction() as sess:
        # The portal or login page might have already generated a CSRF token.
        # If not, let's force one into the session.
        if "_csrf" not in sess:
            sess["_csrf"] = "test_csrf_token_abc123"
        valid_token = sess["_csrf"]
    
    # Now attempt the update WITH the valid token
    resp = client.post(
        "/intern/update-profile", 
        json={"name": "Valid Name Update"}, 
        headers={"X-CSRF-Token": valid_token}
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.data}"
