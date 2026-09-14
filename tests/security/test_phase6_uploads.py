"""
Phase 6 - File Upload Security
Tests magic byte validation on upload endpoints.
"""
import pytest
import io
from app import get_db, allowed_file, sniff_upload_type
from tests.conftest import login_as_intern

def test_allowed_file():
    assert allowed_file("test.png") == True
    assert allowed_file("test.jpg") == True
    assert allowed_file("test.pdf") == True
    assert allowed_file("test.php") == False
    assert allowed_file("test.php.jpg") == True
    assert allowed_file("no_extension") == False

def test_sniff_upload_type():
    class DummyFile:
        def __init__(self, content):
            self.stream = io.BytesIO(content)
            
    assert sniff_upload_type(DummyFile(b"\x89PNG\r\n\x1a\n...")) == "png"
    assert sniff_upload_type(DummyFile(b"\xff\xd8\xff...")) == "jpg"
    assert sniff_upload_type(DummyFile(b"%PDF-1.4...")) == "pdf"
    assert sniff_upload_type(DummyFile(b"<?php echo 'malware'; ?>")) == None

def test_task_submit_rejects_spoofed_file(app_client):
    client, db_path = app_client
    
    # Login and create a task
    from tests.conftest import seed_intern
    intern_id = seed_intern(db_path, "test_upload@test.com", "Pass123", "Intern")
    
    with get_db() as conn:
        conn.execute("INSERT INTO tasks (title, description, is_active) VALUES ('T1', 'Desc', 1)")
        conn.commit()
        task_id = conn.execute("SELECT id FROM tasks").fetchone()["id"]
        
    login_as_intern(client, db_path, "test_upload@test.com", "Pass123")
    
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_csrf_token"
        
    # Attempt to upload a spoofed file
    data = {
        "_csrf_token": "test_csrf_token",
        "submission_file": (io.BytesIO(b"<?php echo 'hack'; ?>"), "malware.pdf")
    }
    
    resp = client.post(
        f"/tasks/{task_id}/submit", 
        data=data,
        content_type="multipart/form-data"
    )
    
    assert resp.status_code == 400
    assert b"File must be a real PNG, JPEG, or PDF" in resp.data
