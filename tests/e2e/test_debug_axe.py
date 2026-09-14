import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Page
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

def print_violations(page_url, page: Page):
    page.goto(page_url)
    results = Axe().run(page)
    violations = results.response.get("violations", [])
    print(f"\n--- {page_url} ---")
    for v in violations:
        if v['id'] == 'color-contrast':
            for node in v.get('nodes', []):
                print(f"Node: {node['target']}")
                print(f"Failure: {node.get('failureSummary')}")

def test_debug_all(page: Page, live_server_url):
    print_violations(live_server_url + "/", page)
    print_violations(live_server_url + "/admin-login", page)
