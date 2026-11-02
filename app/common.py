from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Identity(Contract):
    tenant: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    subject: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    roles: list[Literal["operator", "reviewer", "auditor", "clinician", "support", "privacy"]] = (
        Field(min_length=1, max_length=6)
    )


class DomainError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def require(actor: Identity, role: str) -> None:
    if role not in actor.roles:
        raise DomainError("Role not authorized", 403)


def stamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("Timezone required")
        return result.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise DomainError("Invalid timezone-aware timestamp", 422) from exc


def clock() -> str:
    return datetime.now(UTC).isoformat()


def fresh(observed: str, now: str, hours: int) -> bool:
    age = stamp(now) - stamp(observed)
    return timedelta(0) <= age <= timedelta(hours=hours)


def get(state: dict[str, Any], kind: str, key: str) -> dict[str, Any]:
    item = state.get(kind, {}).get(key)
    if item is None:
        raise DomainError("Record not found", 404)
    return dict(item)


def put(
    state: dict[str, Any], kind: str, key: str, item: dict[str, Any], *, create: bool = False
) -> dict[str, Any]:
    bucket = state.setdefault(kind, {})
    if create and key in bucket:
        raise DomainError("Record already exists")
    if key not in bucket and len(bucket) >= 200:
        raise DomainError("Local record capacity reached", 429)
    bucket[key] = item
    return item


def independent(actor: Identity, subject: str) -> None:
    require(actor, "reviewer")
    if actor.subject == subject:
        raise DomainError("An independent reviewer is required", 403)


class Ref(Contract):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")


class VersionRef(Ref):
    version: int = Field(ge=1, le=1_000_000)


def versioned(item: dict[str, Any], version: int) -> None:
    if item["version"] != version:
        raise DomainError("Record version changed")


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise ValueError("State path must not be a symlink")
        self.path = path
        with self.tx() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS state(tenant TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS receipts(tenant TEXT, key TEXT, request TEXT NOT NULL, response TEXT NOT NULL, PRIMARY KEY(tenant,key));
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, tenant TEXT NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
            """)
        path.chmod(0o600)

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def load(db: sqlite3.Connection, tenant: str) -> dict[str, Any]:
        row = db.execute("SELECT payload FROM state WHERE tenant=?", (tenant,)).fetchone()
        return dict(json.loads(row["payload"])) if row else {}

    @staticmethod
    def audit(
        db: sqlite3.Connection, actor: Identity, action: str, request: str, result: Any, now: str
    ) -> str:
        if (
            db.execute("SELECT count(*) FROM audit WHERE tenant=?", (actor.tenant,)).fetchone()[0]
            >= 5000
        ):
            raise DomainError("Local audit capacity reached", 429)
        row = db.execute(
            "SELECT hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1", (actor.tenant,)
        ).fetchone()
        previous = str(row[0]) if row else "0" * 64
        payload = {
            "tenant": actor.tenant,
            "subject": actor.subject,
            "action": action,
            "request_sha256": request,
            "result_sha256": digest(result),
            "at": now,
        }
        hashed = digest({"previous": previous, "payload": payload})
        db.execute(
            "INSERT INTO audit(tenant,payload,previous,hash) VALUES(?,?,?,?)",
            (actor.tenant, canonical(payload), previous, hashed),
        )
        return hashed

    def evidence(self, actor: Identity) -> dict[str, Any]:
        with self.tx() as db:
            rows = db.execute(
                "SELECT payload,previous,hash FROM audit WHERE tenant=? ORDER BY seq",
                (actor.tenant,),
            ).fetchall()
        previous = "0" * 64
        events = []
        for row in rows:
            payload = json.loads(row[0])
            if row[1] != previous or row[2] != digest({"previous": previous, "payload": payload}):
                raise DomainError("Audit integrity failed", 500)
            previous = row[2]
            events.append({"payload": payload, "previous": row[1], "hash": row[2]})
        return {
            "tenant": actor.tenant,
            "integrity": "verified_local_chain",
            "checkpoint": previous,
            "events": events,
        }


DEMO_IDENTITIES = {
    f"demo-{role}": Identity.model_validate(
        {"tenant": "alder", "subject": subject, "roles": [role]}
    )
    for role, subject in [
        ("operator", "alex"),
        ("reviewer", "blair"),
        ("auditor", "casey"),
        ("clinician", "dr-alex"),
        ("support", "sam"),
        ("privacy", "pat"),
    ]
}
DEMO_IDENTITIES["demo-other"] = Identity(
    tenant="birch",
    subject="other",
    roles=["operator", "reviewer", "auditor", "clinician", "support", "privacy"],
)


def authenticate(header: str, identities: dict[str, Identity]) -> Identity:
    if not header.startswith("Bearer "):
        raise DomainError("Bearer authentication required", 401)
    supplied = header[7:].encode()
    for token, actor in identities.items():
        if secrets.compare_digest(supplied, token.encode()):
            return actor
    raise DomainError("Invalid credentials", 401)
