from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import domain
from app.api import BodyLimit, create_app
from app.cli import DEMO_TIME, demo, resolve
from app.common import (
    DEMO_IDENTITIES,
    DomainError,
    Identity,
    Store,
    authenticate,
    digest,
    fresh,
    get,
    independent,
    put,
    stamp,
)
from app.service import Service


@pytest.fixture
def service(tmp_path: Path) -> Service:
    return Service(Store(tmp_path / "state.db"))


def first_step() -> dict[str, Any]:
    return dict(json.loads(Path("samples/scenario.json").read_text())["steps"][0])


def test_complete_scenario_and_integrity() -> None:
    result = demo()
    assert result["mode"] == "synthetic-offline"
    assert result["evidence"]["integrity"] == "verified_local_chain"
    assert any("expected_denial" in row for row in result["transcript"])


def test_authentication_schema_and_time_fail_closed() -> None:
    for header in ["", "Basic demo-operator", "Bearer wrong", "Bearer démo"]:
        with pytest.raises(DomainError):
            authenticate(header, DEMO_IDENTITIES)
    assert authenticate("Bearer demo-operator", DEMO_IDENTITIES).tenant == "alder"
    with pytest.raises(ValidationError):
        Identity(tenant="../escape", subject="a", roles=["operator"])
    for value in ["bad", "2026-01-01", "2026-13-01T00:00:00Z"]:
        with pytest.raises(DomainError):
            stamp(value)
    assert not fresh("2026-11-02T12:00:00Z", DEMO_TIME, 24)
    assert fresh(DEMO_TIME, DEMO_TIME, 24)


def test_private_state_idempotency_and_cross_actor_conflicts(service: Service) -> None:
    step = first_step()
    data = resolve(step["data"], {}, DEMO_TIME)
    actor = DEMO_IDENTITIES[step["identity"]]
    result = service.execute(actor, step["action"], data, "request-0001", DEMO_TIME)
    assert result == service.execute(actor, step["action"], data, "request-0001", DEMO_TIME)
    with pytest.raises(DomainError):
        service.execute(
            DEMO_IDENTITIES["demo-other"].model_copy(update={"tenant": actor.tenant}),
            step["action"],
            data,
            "request-0001",
            DEMO_TIME,
        )
    assert service.store.path.stat().st_mode & 0o077 == 0
    assert service.store.evidence(DEMO_IDENTITIES["demo-other"])["events"] == []
    with service.store.tx() as db:
        assert service.store.load(db, "birch") == {}


def test_role_rejection_unknown_action_extra_fields_and_rollback(service: Service) -> None:
    step = first_step()
    data = resolve(step["data"], {}, DEMO_TIME)
    with pytest.raises(DomainError):
        service.execute(
            DEMO_IDENTITIES["demo-auditor"], step["action"], data, "denied-0001", DEMO_TIME
        )
    with pytest.raises(ValidationError):
        service.execute(
            DEMO_IDENTITIES["demo-operator"],
            step["action"],
            {**data, "unknown": "sensitive-canary"},
            "denied-0002",
            DEMO_TIME,
        )
    with pytest.raises(DomainError):
        service.execute(DEMO_IDENTITIES["demo-operator"], "unknown", {}, "denied-0003", DEMO_TIME)
    assert service.store.evidence(DEMO_IDENTITIES["demo-reviewer"])["events"] == []
    with service.store.tx() as db:
        assert service.store.load(db, "alder") == {}


def test_concurrent_replay_commits_once(service: Service) -> None:
    step = first_step()
    data = resolve(step["data"], {}, DEMO_TIME)

    def execute(_: int) -> dict[str, Any]:
        return service.execute(
            DEMO_IDENTITIES[step["identity"]], step["action"], data, "concurrent-0001", DEMO_TIME
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(execute, range(8)))
    assert all(row == results[0] for row in results)
    assert len(service.store.evidence(DEMO_IDENTITIES["demo-reviewer"])["events"]) == 1


def test_audit_tampering_detected(service: Service) -> None:
    step = first_step()
    service.execute(
        DEMO_IDENTITIES[step["identity"]],
        step["action"],
        resolve(step["data"], {}, DEMO_TIME),
        "integrity-0001",
        DEMO_TIME,
    )
    with service.store.tx() as db:
        db.execute("UPDATE audit SET hash=?", ("0" * 64,))
    with pytest.raises(DomainError, match="integrity"):
        service.store.evidence(DEMO_IDENTITIES["demo-reviewer"])


def test_capacity_references_and_independent_actor() -> None:
    state: dict[str, Any] = {"item": {str(i): {} for i in range(200)}}
    with pytest.raises(DomainError):
        put(state, "item", "extra", {}, create=True)
    with pytest.raises(DomainError):
        put(state, "item", "1", {}, create=True)
    with pytest.raises(DomainError):
        get(state, "missing", "id")
    actor = Identity(tenant="alder", subject="same", roles=["operator", "reviewer"])
    with pytest.raises(DomainError, match="independent"):
        independent(actor, "same")
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


def test_http_boundaries_and_sanitized_errors(tmp_path: Path) -> None:
    with TestClient(create_app(tmp_path / "http.db", demo=True)) as client:
        assert client.get("/health").json()["mode"] == "synthetic-demo"
        assert client.get("/").headers["content-security-policy"].startswith("default-src 'none'")
        assert client.get("/style.css").status_code == 200
        assert client.get("/api/state").status_code == 401
        assert (
            client.get("/api/state", headers={"Authorization": "Bearer wrong"}).status_code == 401
        )
        assert (
            client.get("/api/state", headers={"Authorization": "Bearer demo-other"}).status_code
            == 200
        )
        assert client.get("/health", headers={"Host": "attacker.invalid"}).status_code == 400
        assert (
            client.get("/health", headers={"Origin": "https://attacker.invalid"}).status_code == 403
        )
        assert client.post("/api/actions", content="{}").status_code == 415
        assert (
            client.post(
                "/api/actions",
                content="{" + '"x":"' + "a" * 262144 + '"}',
                headers={"Content-Type": "application/json", "Content-Length": "1"},
            ).status_code
            == 413
        )
        header = {"Authorization": "Bearer demo-operator"}
        response = client.post(
            "/api/actions",
            json={
                "action": "unknown",
                "data": {"secret": "private-canary"},
                "key": "negative-0001",
            },
            headers=header,
        )
        assert response.status_code == 422 and "private-canary" not in response.text
        response = client.post(
            "/api/actions",
            json={"action": "unknown", "data": {}, "key": "short", "canary": "private-canary"},
            headers=header,
        )
        assert response.status_code == 422 and "private-canary" not in response.text
        assert client.get("/api/evidence", headers=header).status_code == 403
        assert (
            client.get(
                "/api/evidence", headers={"Authorization": "Bearer demo-reviewer"}
            ).status_code
            == 200
        )
    with pytest.raises(ValueError):
        create_app(tmp_path / "missing.db")
    with pytest.raises(ValueError):
        create_app(tmp_path / "mixed.db", DEMO_IDENTITIES, demo=True)
    with TestClient(
        create_app(tmp_path / "configured.db", {"x" * 32: DEMO_IDENTITIES["demo-operator"]})
    ) as client:
        assert client.get("/api/scenario").status_code == 403
        assert (
            client.get("/api/state", headers={"Authorization": "Bearer demo-operator"}).status_code
            == 401
        )


def test_body_disconnect_and_fragment_limit() -> None:
    import asyncio

    called = False

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal called
        called = True
        if scope["type"] == "http":
            message = await receive()
            assert message["body"] == b"abc"

    async def run(messages: list[dict[str, Any]], scope: dict[str, Any]) -> None:
        async def receive() -> dict[str, Any]:
            return messages.pop(0)

        async def send(_: Any) -> None:
            return

        await BodyLimit(app)(scope, receive, send)

    asyncio.run(
        run(
            [
                {"type": "http.request", "body": b"ab", "more_body": True},
                {"type": "http.request", "body": b"c"},
            ],
            {"type": "http"},
        )
    )
    assert called
    called = False
    asyncio.run(
        run(
            [
                {"type": "http.request", "body": b"ab", "more_body": True},
                {"type": "http.disconnect"},
            ],
            {"type": "http"},
        )
    )
    assert not called
    asyncio.run(run([], {"type": "lifespan"}))
    assert called


def test_schema_exports_are_strict() -> None:
    for model in domain.MODELS.values():
        assert model.model_json_schema()["additionalProperties"] is False
