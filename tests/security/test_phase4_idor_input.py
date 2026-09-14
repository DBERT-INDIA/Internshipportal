"""
Phase 4 Security Regression Suite - IDOR & Input Validation
Covers: IDOR/BOLA mitigations across roles, Input boundaries
"""
import pytest
from app import get_db
from tests.conftest import login_as_intern, login_as_company

def test_idor_company_cannot_publish_other_company_post(app_client):
    client, db_path = app_client
    
    # 1. Seed two companies and create a post for Company 1
    from tests.conftest import seed_company
    comp1_id = seed_company(db_path, "comp1@test.com", "Pass123", "Company 1")
    comp2_id = seed_company(db_path, "comp2@test.com", "Pass123", "Company 2")
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO posts (company_id, title, role_type, employment_type, "
            "location_type, location, stipend_type, min_stipend, duration_months, "
            "description, responsibilities, requirements, status, is_live) "
            "VALUES (?, 'Test Post', 'SDE', 'Internship', 'Remote', 'N/A', "
            "'Fixed', 10000, 6, 'Desc', 'Resp', 'Req', 'draft', 0)",
            (comp1_id,)
        )
        conn.commit()
        post_id = conn.execute("SELECT id FROM posts WHERE company_id=?", (comp1_id,)).fetchone()["id"]
        
    # 2. Login as Company 2
    login_as_company(client, db_path, "comp2@test.com", "Pass123")
    
    # 3. Attempt to publish Company 1's post
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_csrf_token"
    
    resp = client.post(f"/company/posts/{post_id}/publish", headers={"X-CSRF-Token": "test_csrf_token"})
    
    # 4. Assert 404 (or 403) due to IDOR protection
    assert resp.status_code == 404
    assert b"Not found" in resp.data

def test_idor_intern_cannot_read_other_intern_notification(app_client):
    client, db_path = app_client
    
    # 1. Seed two interns and a notification for Intern 1
    from tests.conftest import seed_intern
    int1_id = seed_intern(db_path, "intern1@test.com", "Pass123", "Intern 1")
    int2_id = seed_intern(db_path, "intern2@test.com", "Pass123", "Intern 2")
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO notifications (intern_id, message, is_read) VALUES (?, 'Test', 0)",
            (int1_id,)
        )
        conn.commit()
        notif_id = conn.execute("SELECT id FROM notifications WHERE intern_id=?", (int1_id,)).fetchone()["id"]
        
    # 2. Login as Intern 2
    login_as_intern(client, db_path, "intern2@test.com", "Pass123")
    
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_csrf_token"
        
    # 3. Attempt to mark Intern 1's notification as read
    resp = client.post(f"/intern/notifications/{notif_id}/read", headers={"X-CSRF-Token": "test_csrf_token"})
    
    # 4. Assert success response is received BUT the DB is unchanged for the other intern
    # Wait, the endpoint just returns {"status": "success"} blindly! 
    # Let's check if it actually updated Intern 1's notification.
    with get_db() as conn:
        notif = conn.execute("SELECT is_read FROM notifications WHERE id=?", (notif_id,)).fetchone()
        assert notif["is_read"] == 0, "IDOR: Intern 2 marked Intern 1's notification as read!"

def test_input_validation_intern_profile_name_bounds(app_client):
    client, db_path = app_client
    login_as_intern(client, db_path)
    
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_csrf_token"
        
    # Attempt to set an excessively long name (Input Validation / XSS buffer)
    long_name = "A" * 81
    resp = client.post("/intern/update-profile", json={"name": long_name}, headers={"X-CSRF-Token": "test_csrf_token"})
    
    assert resp.status_code == 400
    assert b"Name must be 2\\u201380 characters." in resp.data

def test_input_validation_intern_profile_xss_sanitization(app_client):
    client, db_path = app_client
    login_as_intern(client, db_path)
    
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_csrf_token"
        
    # Send HTML/XSS payload
    xss_payload = "<script>alert(1)</script>"
    resp = client.post("/intern/update-profile", json={"name": xss_payload}, headers={"X-CSRF-Token": "test_csrf_token"})
    
    # It might pass length checks, but let's see how the DB stored it.
    with get_db() as conn:
        intern = conn.execute("SELECT name FROM intern_accounts WHERE email='intern@test.com'").fetchone()
        
    # Clean_text() should have removed tags
    assert "<script>" not in intern["name"]
    assert "script" not in intern["name"] or "&lt;script" in intern["name"] or intern["name"] == ""
