"""
Authorization regression tests.

All authenticated requests use the real login endpoints via the shared fixtures.
Do not mutate Flask session values directly: doing so bypasses authentication.
"""
from tests.conftest import login_as_admin, login_as_intern


def test_public_routes_accessible(app_client):
    client, _db_path = app_client

    response = client.get("/")

    assert response.status_code == 200


def test_admin_routes_reject_anonymous_users(app_client):
    client, _db_path = app_client

    response = client.get("/admin/csv/enrollments")

    assert response.status_code == 401


def test_intern_routes_reject_anonymous_users(app_client):
    client, _db_path = app_client

    response = client.get("/intern/my-applications")

    assert response.status_code == 401


def test_intern_cannot_access_admin_routes(app_client):
    client, db_path = app_client
    login_as_intern(
        client,
        db_path,
        email="rbac_intern@example.test",
        password="InternPass123!",
    )

    response = client.get("/admin/csv/enrollments")

    assert response.status_code == 401


def test_admin_can_access_admin_routes(app_client):
    client, db_path = app_client
    login_as_admin(
        client,
        db_path,
        email="rbac_admin@example.test",
        password="AdminPass123!",
    )

    response = client.get("/admin/csv/enrollments")

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
