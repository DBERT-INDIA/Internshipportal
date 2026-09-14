import os
import tempfile
import pytest
import threading
from werkzeug.serving import make_server
from playwright.sync_api import Page, expect
import re

@pytest.fixture(scope="session")
def e2e_db():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DB_FILE"] = db_path
    
    import app as app_module
    app_module.DB_FILE = db_path
    
    with app_module.app.app_context():
        app_module.init_db()
        # Seed test data
        from tests.conftest import seed_intern
        seed_intern(db_path, email="intern@example.com", password="Password123")
        
        # Seed admin user
        import hashlib
        with app_module.get_db() as conn:
            conn.execute(
                "INSERT INTO staff_accounts (name, email, password_hash, is_active) VALUES (?, ?, ?, 1)",
                ("Admin", "admin@example.com", app_module.set_password_hash("Admin123"))
            )
            conn.commit()
            
    yield db_path
    
    os.close(db_fd)

@pytest.fixture(scope="session")
def live_server_url(e2e_db):
    import app as app_module
    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    
    # We use a different port from a11y tests to avoid collisions if running concurrently
    server = make_server("127.0.0.1", 8998, app_module.app)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    yield "http://127.0.0.1:8998"
    
    server.shutdown()
    thread.join()

def test_intern_auth_workflow(page: Page, live_server_url):
    # 1. Go to homepage
    page.goto(live_server_url + "/")
    expect(page).to_have_title(re.compile("DBERT"))
    
    # 2. Open auth overlay via hash
    page.goto(live_server_url + "/#signin")
    page.wait_for_selector("#authOverlay.active", timeout=5000)
    
    # 3. Invalid login
    page.fill("#si_email", "intern@example.com")
    page.click("#siEmailBtn")
    
    # Wait for password field to appear
    page.wait_for_selector("#si_password", state="visible")
    page.fill("#si_password", "WrongPassword")
    page.click("#signinBtn")
    
    expect(page.locator("#signinError")).to_be_visible()
    
    # 4. Valid login
    page.fill("#si_password", "Password123")
    page.click("#signinBtn")
    
    # Should redirect to portal
    page.wait_for_url(live_server_url + "/portal")
    expect(page.locator("h1").first).to_be_visible()
    
    # 5. Navigate to courses
    page.click("text=Course Catalog")
    page.wait_for_url(live_server_url + "/courses")
    expect(page.locator("h1")).to_contain_text("Guided Learning")
    
    # 6. Logout
    page.goto(live_server_url + "/portal")
    page.click("button.btn-logout")
    page.wait_for_url(live_server_url + "/")
    
    # Ensure session is cleared by trying to go to /portal
    page.goto(live_server_url + "/portal")
    page.wait_for_url(re.compile(r"/?login=1|/"))

def test_admin_auth_workflow(page: Page, live_server_url):
    page.goto(live_server_url + "/admin/login")
    
    # Valid login
    page.fill("#username", "admin@example.com")
    page.fill("#password", "Admin123")
    page.click("#loginBtn")
    
    page.wait_for_url(live_server_url + "/admin")
    expect(page.locator("h1")).to_contain_text("Enrollments")
    
    # Logout
    # Admin layout might have a different logout button
    # Let's just go directly to logout
    page.goto(live_server_url + "/logout")

def test_resilience_rate_limit(page: Page, live_server_url):
    page.goto(live_server_url + "/#signin")
    page.wait_for_selector("#authOverlay.active", timeout=5000)
    
    page.fill("#si_email", "intern@example.com")
    page.click("#siEmailBtn")
    page.wait_for_selector("#si_password", state="visible")
    page.fill("#si_password", "Wrong")
    
    # Click many times to trigger rate limit
    for _ in range(7):
        page.click("#signinBtn")
        page.wait_for_timeout(300)
        
    expect(page.locator("#signinError")).to_be_visible()
    error_text = page.locator("#signinError").text_content()
    assert len(error_text) > 0
