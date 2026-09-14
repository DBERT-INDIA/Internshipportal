import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Page, expect
import threading
from werkzeug.serving import make_server

@pytest.fixture(scope="session")
def live_server_url():
    from app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    
    server = make_server("127.0.0.1", 8999, app)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    yield "http://127.0.0.1:8999"
    
    server.shutdown()
    thread.join()

def test_a11y_homepage(page: Page, live_server_url):
    page.goto(live_server_url + "/")
    page.wait_for_timeout(1500)
    results = Axe().run(page)
    violations = results.response.get("violations", [])
    assert len(violations) == 0, f"Found {len(violations)} accessibility violations on Homepage"


def test_a11y_admin_login(page: Page, live_server_url):
    page.goto(live_server_url + "/admin-login")
    page.wait_for_timeout(1000)
    results = Axe().run(page)
    violations = results.response.get("violations", [])
    assert len(violations) == 0, f"Found {len(violations)} accessibility violations on /admin-login"

def test_a11y_courses_catalog(page: Page, live_server_url):
    page.goto(live_server_url + "/courses")
    page.wait_for_timeout(1000)
    results = Axe().run(page)
    violations = results.response.get("violations", [])
    assert len(violations) == 0, f"Found {len(violations)} accessibility violations on /courses"
