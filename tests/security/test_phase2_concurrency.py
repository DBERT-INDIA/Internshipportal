"""
Phase 2 Security & Concurrency Regression Suite
Covers: PAY-001 (Mentor slots), PAY-002 (Cohort seats), DATA-001 (State Machine)
"""
import pytest
import sqlite3
import threading
from app import get_db

@pytest.fixture
def phase2_setup(app_client):
    client, db_path = app_client
    import os
    os.environ["DB_FILE"] = db_path
    
    from tests.conftest import seed_intern
    # Create two interns for concurrency tests
    i1 = seed_intern(db_path, "intern1@test.com", "TestPass123", "Intern 1")
    i2 = seed_intern(db_path, "intern2@test.com", "TestPass123", "Intern 2")
    
    # Create test data
    with get_db() as conn:
        # Mentor slot
        conn.execute("INSERT OR REPLACE INTO mentor_availability_slots (id, mentor_staff_id, is_booked, start_time, end_time) VALUES (999, 1, 0, '2026-01-01 10:00:00', '2026-01-01 11:00:00')")
        # Cohort
        conn.execute("INSERT OR REPLACE INTO cohorts (id, title, capacity, status, company_id) VALUES (888, 'Test Cohort', 1, 'published', 1)")
        # Project submission dependencies
        conn.execute("INSERT OR IGNORE INTO courses (id, title, slug, domain, company_id) VALUES (1, 'Test Course', 'test-course', 'Test', 1)")
        conn.execute(
            "INSERT OR REPLACE INTO project_submissions (id, intern_id, course_id, status, enrollment_id, github_repo_url, project_title, project_description) VALUES (777, ?, 1, 'pending', 1, 'url', 'title', 'desc')",
            (i1,)
        )
        # Clear existing mentor bookings and cohort enrollments to prevent fixture pollution
        conn.execute("DELETE FROM mentor_session_bookings")
        conn.execute("DELETE FROM cohort_enrollments WHERE cohort_id=888")
        conn.commit()
    
    return client, db_path

def test_pay001_mentor_slot_atomic_booking(phase2_setup):
    client, db_path = phase2_setup
    from tests.conftest import login_as_intern
    
    # Intern 1 books the slot
    login_as_intern(client, db_path, "intern1@test.com", "TestPass123")
    resp1 = client.post("/mentors/slots/999/book")
    assert resp1.status_code == 200, f"First booking should succeed: {resp1.get_data(as_text=True)}"
    
    # Intern 2 tries to book the same slot
    login_as_intern(client, db_path, "intern2@test.com", "TestPass123")
    resp2 = client.post("/mentors/slots/999/book")
    assert resp2.status_code == 400, "Second booking should fail with 400"
    assert "no longer available" in resp2.get_json()["message"]

def test_pay002_cohort_capacity_atomic_enrollment(phase2_setup):
    client, db_path = phase2_setup
    from tests.conftest import login_as_intern
    
    # Intern 1 enrolls in cohort (capacity 1)
    login_as_intern(client, db_path, "intern1@test.com", "TestPass123")
    resp1 = client.post("/cohorts/888/enroll")
    assert resp1.status_code == 200, f"First enrollment should succeed: {resp1.status_code} {resp1.get_data(as_text=True)}"
    
    # Intern 2 tries to enroll in same cohort
    login_as_intern(client, db_path, "intern2@test.com", "TestPass123")
    resp2 = client.post("/cohorts/888/enroll")
    assert resp2.status_code == 409, "Second enrollment should fail with 409"
    assert "full" in resp2.get_json()["message"]

def test_data001_project_submission_atomic_review(phase2_setup):
    client, db_path = phase2_setup
    
    from app import create_session
    import os
    os.environ["DB_FILE"] = db_path
    
    with client.session_transaction() as sess:
        sess["staff_id"] = 1
        sess["role"] = "admin"
        
    resp1 = client.post("/staff/projects/777/decision", json={"decision": "approved"})
    assert resp1.status_code in (200, 302, 201), f"First review failed: {resp1.get_data(as_text=True)}"
    
    resp2 = client.post("/staff/projects/777/decision", json={"decision": "approved"})
    assert resp2.status_code == 400, "DATA-001: Second review should be rejected"
    assert "already processed" in resp2.get_json()["message"]
