import pytest
import app as app_module
from agentguard.db import connect

def test_bundled_app_is_seeded():
    client = app_module.app.test_client()
    resp = client.get("/api/apps")
    assert resp.status_code == 200
    apps = resp.get_json()
    assert len(apps) >= 1
    assert any(a["id"] == 1 and "Bundled" in a["name"] for a in apps)

def test_create_custom_application():
    client = app_module.app.test_client()
    resp = client.post("/app/create", data={
        "name": "Custom Weather API",
        "description": "Production weather microservice",
        "base_url": "http://127.0.0.1:5000/sut",
        "app_type": "REST API",
        "auth_confirmed": "1"
    }, follow_redirects=True)
    assert resp.status_code == 200

    resp_apps = client.get("/api/apps")
    apps = resp_apps.get_json()
    assert any(a["name"] == "Custom Weather API" for a in apps)

def test_external_url_requires_auth_confirmation():
    client = app_module.app.test_client()
    # Attempt to register an external URL without auth_confirmed
    resp = client.post("/app/create", data={
        "name": "External Unconfirmed Service",
        "base_url": "https://api.github.com",
        "app_type": "REST API"
    }, follow_redirects=True)
    assert resp.status_code == 200
    # Should not be in apps
    resp_apps = client.get("/api/apps")
    apps = resp_apps.get_json()
    assert not any(a["name"] == "External Unconfirmed Service" for a in apps)

def test_cannot_delete_default_bundled_app():
    client = app_module.app.test_client()
    resp = client.post("/app/delete/1", follow_redirects=True)
    assert resp.status_code == 200
    resp_apps = client.get("/api/apps")
    apps = resp_apps.get_json()
    assert any(a["id"] == 1 for a in apps)
