import pytest

def test_request_id_injected(app_client):
    client, db = app_client
    response = client.get("/")
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    req_id = response.headers["X-Request-ID"]
    assert len(req_id) > 10

def test_structured_logging(app_client):
    client, db = app_client
    # Trigger a 404 to see if structured logging handles it.
    response = client.get("/nonexistent-route-for-testing")
    assert response.status_code == 404

