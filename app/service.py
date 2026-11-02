from __future__ import annotations

import json
from typing import Any

from app import domain
from app.common import DomainError, Identity, Store, canonical, digest, require


class Service:
    def __init__(self, store: Store):
        self.store = store

    def execute(
        self, actor: Identity, action: str, data: dict[str, Any], key: str, now: str
    ) -> dict[str, Any]:
        model = domain.MODELS.get(action)
        if model is None:
            raise DomainError("Unsupported action", 422)
        validated = model.model_validate(data)
        request_hash = digest(
            {
                "subject": actor.subject,
                "roles": actor.roles,
                "action": action,
                "data": validated.model_dump(),
            }
        )
        with self.store.tx() as db:
            existing = db.execute(
                "SELECT request,response FROM receipts WHERE tenant=? AND key=?",
                (actor.tenant, key),
            ).fetchone()
            if existing:
                if existing[0] != request_hash:
                    raise DomainError("Idempotency key belongs to a different request")
                return dict(json.loads(existing[1]))
            state = self.store.load(db, actor.tenant)
            result = domain.dispatch(state, actor, action, validated, now)
            checkpoint = self.store.audit(db, actor, action, request_hash, result, now)
            db.execute(
                "INSERT INTO state VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET payload=excluded.payload",
                (actor.tenant, canonical(state)),
            )
            response = {"result": result, "checkpoint": checkpoint}
            db.execute(
                "INSERT INTO receipts VALUES(?,?,?,?)",
                (actor.tenant, key, request_hash, canonical(response)),
            )
            return response

    def view(self, actor: Identity, now: str) -> dict[str, Any]:
        with self.store.tx() as db:
            state = self.store.load(db, actor.tenant)
            result = domain.view(state, actor, now)
            self.store.audit(
                db, actor, "read-summary", digest({"subject": actor.subject}), result, now
            )
            return result

    def evidence(self, actor: Identity) -> dict[str, Any]:
        require(actor, "reviewer")
        return self.store.evidence(actor)
