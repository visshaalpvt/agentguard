"""Deterministic AI-agent-style system under test (SUT), using synthetic data."""
from flask import Blueprint, jsonify, request

sut = Blueprint("sut", __name__)
DEMO_USERS = {"alice": {"display_name": "Alice Demo", "plan": "standard"},
              "bob": {"display_name": "Bob Demo", "plan": "premium"}}

def run_agent(message, user_id="alice", inject_timeout_bug=False):
    if not isinstance(message, str) or not message.strip():
        return {"ok": False, "error": "message_required", "tool": None}, 400
    normalized = message.lower()
    # Security guard: untrusted prompt text never grants permission to invoke tools.
    if "ignore all rules" in normalized or "reveal secrets" in normalized:
        return {"ok": False, "error": "unsafe_instruction_rejected", "tool": None}, 403
    if "weather" in normalized:
        return {"ok": True, "intent": "weather", "tool": "weather_lookup", "result": "Synthetic weather: 28 C", "user_id": user_id}, 200
    if "profile" in normalized:
        return {"ok": True, "intent": "profile", "tool": "profile_lookup", "result": "Profile request accepted", "user_id": user_id}, 200
    if "timeout" in normalized:
        if inject_timeout_bug:
            return {"ok": True, "intent": "action", "tool": "action_runner", "result": "Action completed"}, 200
        return {"ok": False, "error": "tool_timeout", "tool": "action_runner"}, 504
    return {"ok": False, "error": "unknown_intent", "tool": None, "message": "Please clarify your request"}, 422

@sut.get("/health")
def health():
    response = jsonify({"status": "ok", "service": "AgentGuard demo SUT", "version": "1.0"})
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

@sut.post("/agent")
def agent_endpoint():
    body = request.get_json(silent=True) or {}
    result, status = run_agent(body.get("message"), body.get("user_id", "alice"),
                               bool(current_app_config_bug()))
    return jsonify(result), status

def current_app_config_bug():
    # Import inside function avoids module-level Flask app coupling.
    from flask import current_app
    return current_app.config.get("INJECT_TIMEOUT_BUG", False)

@sut.get("/profile/<profile_user>")
def profile(profile_user):
    requester = request.headers.get("X-User-ID", "")
    if requester != profile_user:
        return jsonify({"ok": False, "error": "forbidden"}), 403
    if profile_user not in DEMO_USERS:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "profile": DEMO_USERS[profile_user]})
