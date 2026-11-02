from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

import uvicorn

from app.api import create_app
from app.common import DEMO_IDENTITIES, DomainError, Identity, Store, stamp
from app.service import Service

DEMO_TIME = "2026-11-01T12:00:00Z"


def resolve(value: Any, outputs: dict[str, Any], now: str) -> Any:
    if isinstance(value, str):
        if value == "$now":
            return now
        if value == "$future":
            return (stamp(now) + timedelta(days=1)).isoformat()
        if value == "$past":
            return (stamp(now) - timedelta(days=2)).isoformat()
        if value.startswith("$"):
            parts = value[1:].split(".")
            result: Any = outputs
            for part in parts:
                result = result[part]
            return result
    if isinstance(value, dict):
        return {key: resolve(item, outputs, now) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, outputs, now) for item in value]
    return value


def run_scenario(service: Service, now: str) -> dict[str, Any]:
    scenario = json.loads(Path("samples/scenario.json").read_text())
    outputs: dict[str, Any] = {}
    transcript = []
    for index, step in enumerate(scenario["steps"]):
        actor = DEMO_IDENTITIES[step["identity"]]
        data = resolve(step["data"], outputs, now)
        try:
            result = service.execute(actor, step["action"], data, f"scenario-{index:04d}", now)[
                "result"
            ]
            if step.get("expect_error"):
                raise AssertionError("Expected scenario denial did not occur")
            outputs[step["id"]] = result
            transcript.append({"step": step["title"], "result": result})
        except DomainError as exc:
            if exc.status != step.get("expect_error"):
                raise
            transcript.append(
                {"step": step["title"], "expected_denial": exc.status, "reason": str(exc)}
            )
    reviewer = DEMO_IDENTITIES["demo-reviewer"]
    return {
        "mode": "synthetic-offline",
        "transcript": transcript,
        "summary": service.view(reviewer, now),
        "evidence": service.evidence(reviewer),
    }


def demo() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        previous = os.environ.get("PKI_ROOT")
        os.environ["PKI_ROOT"] = str(Path(directory) / "pki")
        try:
            result = run_scenario(Service(Store(Path(directory) / "state.db")), DEMO_TIME)
            from app.pki import live_exchange

            result["tls_demo"] = live_exchange(Path(directory) / "tls")
            return result
        finally:
            if previous is None:
                os.environ.pop("PKI_ROOT", None)
            else:
                os.environ["PKI_ROOT"] = previous


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["demo", "serve", "schemas"])
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.command == "demo":
        print(json.dumps(demo(), indent=2))
        return
    if args.command == "schemas":
        from app.domain import MODELS

        print(
            json.dumps(
                {name: model.model_json_schema() for name, model in MODELS.items()}, indent=2
            )
        )
        return
    identities = None
    if not args.demo:
        credential_file = Path(os.environ["IDENTITY_FILE"])
        if credential_file.is_symlink() or credential_file.stat().st_mode & 0o077:
            raise ValueError("Identity file must be a private regular file")
        raw = json.loads(credential_file.read_text())
        if (
            not raw
            or len(raw) > 100
            or any(len(token) < 32 or token.startswith("demo-") for token in raw)
        ):
            raise ValueError("Provide at most 100 non-demo credentials with at least 32 characters")
        identities = {token: Identity.model_validate(value) for token, value in raw.items()}
    host = os.environ.get("HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "0.0.0.0"}:
        raise ValueError("Only local lab binds are supported")
    app = create_app(
        Path(os.environ.get("STATE_PATH", "artifacts/state.db")), identities, demo=args.demo
    )
    uvicorn.run(
        app, host=host, port=args.port, access_log=False, limit_concurrency=32, timeout_keep_alive=5
    )


if __name__ == "__main__":
    main()
