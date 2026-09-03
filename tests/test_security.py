from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone

import jwt

from backend import app as app_module


def test_api1_object_access_is_bound_to_authenticated_team(client, register):
    alpha, alpha_auth = register("Alpha")
    bravo, bravo_auth = register("Bravo")

    own = client.get(f"/api/user/{alpha['profileId']}", headers=alpha_auth)
    assert own.status_code == 200
    assert own.get_json()["user"]["id"] == alpha["profileId"]
    assert "secret_note" not in own.get_json()["user"]

    assert client.get(f"/api/user/{bravo['profileId']}", headers=alpha_auth).status_code == 403
    assert client.get("/api/game/state/Alpha", headers=bravo_auth).status_code == 403
    assert client.get(f"/api/user/{alpha['profileId']}").status_code == 401


def test_api2_forged_and_expired_tokens_are_rejected(client, register):
    team, auth = register()
    forged = jwt.encode(
        {"sub": "team:1", "team_id": 1, "team": "Alpha", "role": "team"},
        "attacker-controlled-secret-that-is-long-enough",
        algorithm="HS256",
    )
    assert client.get(
        f"/api/user/{team['profileId']}", headers={"Authorization": f"Bearer {forged}"}
    ).status_code == 401

    now = datetime.now(timezone.utc)
    expired = jwt.encode(
        {
            "iss": app_module.JWT_ISSUER,
            "aud": app_module.JWT_AUDIENCE,
            "sub": f"team:{team['profileId']}",
            "team_id": team["profileId"],
            "team": "Alpha",
            "user_id": team["profileId"],
            "role": "team",
            "nonce": "wrong-even-if-token-were-current",
            "iat": now - timedelta(hours=2),
            "nbf": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
        },
        app_module.SECRET,
        algorithm="HS256",
    )
    assert client.get(
        f"/api/user/{team['profileId']}", headers={"Authorization": f"Bearer {expired}"}
    ).status_code == 401
    assert client.get("/api/admin", headers=auth).status_code == 401
    assert "sample_token" not in (client.get("/api/admin").get_json() or {})


def test_api3_mass_assignment_is_rejected(client, register):
    team, auth = register()
    rejected = client.put(
        "/api/user/update",
        json={"name": "Alice", "role": "admin", "balance": 999999},
        headers=auth,
    )
    assert rejected.status_code == 400
    assert set(rejected.get_json()["fields"]) == {"balance", "role"}

    accepted = client.put(
        "/api/user/update",
        json={"name": "Alice Updated", "email": "alice.updated@example.test"},
        headers=auth,
    )
    assert accepted.status_code == 200
    assert accepted.get_json()["user"]["role"] == "user"
    profile = client.get(f"/api/user/{team['profileId']}", headers=auth).get_json()["user"]
    assert profile["balance"] == 1000


def test_api4_hard_rate_limit_never_turns_into_success(client, register):
    _, auth = register()
    responses = [client.get("/api/rate-limited", headers=auth) for _ in range(8)]
    assert [response.status_code for response in responses[:5]] == [200] * 5
    assert [response.status_code for response in responses[5:]] == [429] * 3
    assert responses[5].headers["Retry-After"]
    assert all("flag" not in (response.get_json() or {}) for response in responses)


def test_api5_admin_functions_require_separate_admin_credential(client, register):
    _, team_auth = register()
    assert client.delete("/api/admin/users").status_code == 401
    assert client.delete("/api/admin/users", headers=team_auth).status_code == 401

    admin_headers = {"X-Admin-Token": os.environ["DVAPI_ADMIN_TOKEN"]}
    allowed = client.delete("/api/admin/users", headers=admin_headers)
    assert allowed.status_code == 200
    assert allowed.get_json()["deleted"] == []


def test_api6_transfer_validates_flow_and_is_idempotent(client, register):
    team, auth = register()
    assert client.post(
        "/api/transfer",
        json={"to": "Bob", "amount": -999},
        headers={**auth, "Idempotency-Key": "negative-amount"},
    ).status_code == 400
    assert client.post("/api/transfer", json={"to": "Bob", "amount": 10}, headers=auth).status_code == 400

    first_headers = {**auth, "Idempotency-Key": "transfer-0001"}
    first = client.post("/api/transfer", json={"to": "Bob", "amount": 100}, headers=first_headers)
    replay = client.post("/api/transfer", json={"to": "Bob", "amount": 100}, headers=first_headers)
    assert first.status_code == replay.status_code == 200
    assert replay.get_json()["idempotent_replay"] is True

    for index in range(2, 6):
        response = client.post(
            "/api/transfer",
            json={"to": "Bob", "amount": 100},
            headers={**auth, "Idempotency-Key": f"transfer-{index:04d}"},
        )
        assert response.status_code == 200
    limited = client.post(
        "/api/transfer",
        json={"to": "Bob", "amount": 1},
        headers={**auth, "Idempotency-Key": "transfer-0006"},
    )
    assert limited.status_code == 429
    profile = client.get(f"/api/user/{team['profileId']}", headers=auth).get_json()["user"]
    assert profile["balance"] == 500


def test_api7_ssrf_destinations_are_default_denied_without_network_access(client, register):
    _, auth = register()
    metadata = client.post(
        "/api/fetch-url",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers=auth,
    )
    external = client.post(
        "/api/fetch-url", json={"url": "https://example.com"}, headers=auth
    )
    assert metadata.status_code == 400
    assert external.status_code == 403
    assert client.get("/api/internal/flag").status_code == 404


def test_api8_debug_data_is_not_exposed_and_headers_are_hardened(client):
    response = client.get("/api/debug?crash=1")
    assert response.status_code == 404
    body = response.get_json()
    assert "traceback" not in body
    assert "flag" not in body
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "Access-Control-Allow-Origin" not in response.headers
    assert client.get("/api/does-not-exist").status_code == 404


def test_api9_deprecated_inventory_is_retired_and_current_data_is_minimized(client, register):
    team, auth = register()
    retired = client.get("/api/v1/users")
    assert retired.status_code == 410
    assert retired.headers["Deprecation"] == "true"
    assert "users" not in retired.get_json()

    current = client.get("/api/v2/users", headers=auth)
    assert current.status_code == 200
    assert current.get_json()["users"] == [{"id": team["profileId"], "name": "Alpha"}]
    assert client.get("/api/v2/users").status_code == 401


def test_api10_webhooks_require_hmac_freshness_schema_and_replay_protection(client):
    raw = json.dumps({"event": "ping", "payload": "hello"}, separators=(",", ":"))
    assert client.post("/api/webhook", data=raw, content_type="application/json").status_code == 401

    timestamp = str(int(time.time()))
    digest = hmac.new(
        os.environ["DVAPI_WEBHOOK_SECRET"].encode(),
        timestamp.encode("ascii") + b"." + raw.encode(),
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Signature": f"sha256={digest}",
        "Content-Type": "application/json",
    }
    accepted = client.post("/api/webhook", data=raw, headers=headers)
    replay = client.post("/api/webhook", data=raw, headers=headers)
    assert accepted.status_code == 202
    assert replay.status_code == 409


def test_team_impersonation_reset_data_exposure_and_retired_flags(client, register):
    alpha, alpha_auth = register("Alpha", ["Private Member"])
    duplicate = client.post(
        "/api/game/register", json={"teamName": "Alpha", "members": ["Attacker"]}
    )
    assert duplicate.status_code == 401

    bravo, bravo_auth = register("Bravo")
    cross_team = client.post(
        "/api/game/register",
        json={"teamName": "Alpha", "members": ["Attacker"]},
        headers=bravo_auth,
    )
    assert cross_team.status_code == 403
    assert client.get("/api/game/state/Alpha").status_code == 401
    assert client.get("/api/game/state/Alpha", headers=alpha_auth).status_code == 200

    leaderboard = client.get("/api/game/leaderboard").get_json()
    assert leaderboard["teams"]
    assert all(set(team) == {"name", "points", "total_time_seconds"} for team in leaderboard["teams"])
    assert "Private Member" not in json.dumps(leaderboard)

    assert client.post("/api/game/restart", json={"fullReset": True}).status_code == 401
    assert client.post("/api/game/submit-flag", json={}, headers=alpha_auth).status_code == 410
    assert client.post("/api/ultimate-challenge", json={}).status_code == 410
    assert alpha["accessToken"] != bravo["accessToken"]


def test_registration_business_flow_is_rate_limited(client):
    responses = [
        client.post(
            "/api/game/register",
            json={"teamName": f"Team-{index}", "members": ["Student"]},
        )
        for index in range(app_module.REGISTRATION_LIMIT + 1)
    ]
    assert all(response.status_code == 200 for response in responses[:-1])
    assert responses[-1].status_code == 429
    assert responses[-1].headers["Retry-After"]


def test_request_body_limit_and_frontend_dynamic_rendering_controls(client):
    oversized = {"teamName": "A" * 20000, "members": ["Student"]}
    assert client.post("/api/game/register", json=oversized).status_code == 413

    frontend_source = (
        app_module.STATIC_DIR / "app.js"
    ).read_text(encoding="utf-8")
    assert "X-Team-Name" not in frontend_source
    assert "li.innerHTML" not in frontend_source
    assert "root.innerHTML" not in frontend_source
    assert "escapeHtml(meta.codename)" in frontend_source
    assert "list.replaceChildren()" in frontend_source
    assert "value.textContent = text" in frontend_source


def test_hardened_catalog_exposes_complete_learning_guide(client):
    response = client.get("/api/challenges")
    assert response.status_code == 200
    body = response.get_json()
    assert body["mode"] == "hardened"
    assert len(body["challenges"]) == 10

    required = {"risk_before", "root_cause", "controls", "code_changes", "tests"}
    for expected_id, challenge in enumerate(body["challenges"], start=1):
        assert challenge["id"] == expected_id
        assert required <= set(challenge["guide"])
        assert challenge["guide"]["controls"]
        assert challenge["guide"]["code_changes"]
        assert challenge["guide"]["tests"]
        assert all("expected" in test for test in challenge["guide"]["tests"])


def test_hardened_guide_and_test_identity_ignore_legacy_session_completion(client):
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute(
            "UPDATE game_session SET ended = 1, running = 0, remaining_seconds = 0 WHERE id = 1"
        )
        db.commit()

    registered = client.post(
        "/api/game/register",
        json={"teamName": "Post-Hardening Reviewer", "members": ["Security Student"]},
    )
    assert registered.status_code == 200
    assert registered.get_json()["assignedChallenge"] == 1

    frontend_source = (app_module.STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "if (!state.hardened && data.ended) endGame();" in frontend_source
    assert "if (!state.hardened && state.session.ended)" in frontend_source
    reset_action = frontend_source.index('if (action === "full-reset")')
    local_reset = frontend_source.index("if (state.hardened)", reset_action)
    admin_prompt = frontend_source.index("Enter the administrator token", reset_action)
    assert local_reset < admin_prompt
    assert "لن تُمسح قاعدة البيانات ولن تحتاج رمز المدير" in frontend_source
