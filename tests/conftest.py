from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


_TEMP_DIR = tempfile.TemporaryDirectory(prefix="api-heist-security-tests-")
os.environ["DVAPI_DB"] = str(Path(_TEMP_DIR.name) / "security-tests.db")
os.environ["DVAPI_SECRET"] = "test-signing-secret-which-is-longer-than-thirty-two-characters"
os.environ["DVAPI_ADMIN_TOKEN"] = "test-admin-token-which-is-longer-than-thirty-two-characters"
os.environ["DVAPI_WEBHOOK_SECRET"] = "test-webhook-secret-which-is-longer-than-thirty-two-characters"
os.environ["DVAPI_FETCH_ALLOWLIST"] = ""

from backend import app as app_module  # noqa: E402


@pytest.fixture()
def client():
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_state(client):
    response = client.post(
        "/api/game/restart",
        json={"fullReset": True},
        headers={"X-Admin-Token": os.environ["DVAPI_ADMIN_TOKEN"]},
    )
    assert response.status_code == 200


@pytest.fixture()
def register(client):
    def _register(name: str = "Alpha", members: list[str] | None = None):
        response = client.post(
            "/api/game/register",
            json={"teamName": name, "members": members or ["Security Student"]},
        )
        assert response.status_code == 200
        body = response.get_json()
        return body, {"Authorization": f"Bearer {body['accessToken']}"}

    return _register
