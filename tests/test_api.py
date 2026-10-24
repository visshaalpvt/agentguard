import app as app_module

def test_health_api_contract():
    client = app_module.app.test_client()
    response = client.get("/sut/health")
    assert response.status_code == 200
    assert response.is_json
    assert response.get_json()["status"] == "ok"

def test_agent_api_requires_message():
    client = app_module.app.test_client()
    response = client.post("/sut/agent", json={})
    assert response.status_code == 400
    assert response.get_json()["error"] == "message_required"

def test_cross_user_profile_access_denied():
    client = app_module.app.test_client()
    response = client.get("/sut/profile/bob", headers={"X-User-ID":"alice"})
    assert response.status_code == 403
