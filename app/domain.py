from __future__ import annotations

from typing import Any, Literal

from cryptography.hazmat.primitives import hashes, serialization
from pydantic import Field

from app.common import (
    Contract,
    DomainError,
    Identity,
    Ref,
    digest,
    get,
    independent,
    put,
    require,
    stamp,
)
from app.pki import authority, validate_csr


class CertificateRequest(Ref):
    name: Literal[
        "localhost", "api.certrelay.test", "database.certrelay.test", "operator.certrelay.test"
    ]
    usage: Literal["server", "client"]
    csr_pem: str = Field(min_length=100, max_length=4096)
    lifetime_minutes: int = Field(ge=1, le=60)
    renews: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9-]{0,63}$")


class Approval(Ref):
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Revocation(Ref):
    reason: Literal["key-compromise", "retired", "superseded"]


MODELS: dict[str, type[Contract]] = {
    "request-certificate": CertificateRequest,
    "approve-certificate": Approval,
    "issue-certificate": Ref,
    "revoke-certificate": Revocation,
    "export-crl": Contract,
}


def dispatch(
    state: dict[str, Any], actor: Identity, action: str, value: Contract, now: str
) -> dict[str, Any]:
    data = value.model_dump()
    if action == "request-certificate":
        require(actor, "operator")
        validate_csr(data["csr_pem"], data["name"])
        if data["renews"]:
            original = get(state, "certificate", data["renews"])
            if (
                original["status"] != "issued"
                or original["requested_by"] != actor.subject
                or original["name"] != data["name"]
                or original["usage"] != data["usage"]
                or stamp(original["not_after"]) <= stamp(now)
            ):
                raise DomainError(
                    "Renewal source is expired, revoked or outside the holder scope", 403
                )
        record = {
            **data,
            "requested_by": actor.subject,
            "requested_at": now,
            "status": "pending",
            "approved_by": None,
        }
        record["request_sha256"] = digest(record)
        return put(state, "certificate", data["id"], record, create=True)
    if action == "export-crl":
        require(actor, "reviewer")
        serials = [
            int(c["serial"])
            for c in state.get("certificate", {}).values()
            if c["status"] == "revoked"
        ]
        return {
            "crl_pem": authority(actor.tenant).crl(serials).decode(),
            "enforcement": "relying_services_must_load_current_crl",
        }
    record = get(state, "certificate", data["id"])
    if action == "approve-certificate":
        independent(actor, record["requested_by"])
        if record["status"] != "pending" or record["request_sha256"] != data["request_sha256"]:
            raise DomainError("Issuance request changed or already decided")
        record.update(status="approved", approved_by=actor.subject)
    elif action == "issue-certificate":
        require(actor, "operator")
        if record["requested_by"] != actor.subject or record["status"] != "approved":
            raise DomainError("Only the approved request holder may issue", 403)
        if record["renews"]:
            original = get(state, "certificate", record["renews"])
            if original["status"] != "issued" or stamp(original["not_after"]) <= stamp(now):
                raise DomainError("Renewal authorization source is no longer active", 403)
        certificate = authority(actor.tenant).issue(
            record["csr_pem"], record["name"], record["usage"], record["lifetime_minutes"]
        )
        record.update(
            status="issued",
            serial=str(certificate.serial_number),
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode(),
            fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            not_after=certificate.not_valid_after_utc.isoformat(),
            ca_pem=authority(actor.tenant).cert.public_bytes(serialization.Encoding.PEM).decode(),
        )
    else:
        require(actor, "reviewer")
        if record["status"] != "issued":
            raise DomainError("Only issued certificates may be revoked")
        record.update(
            status="revoked",
            revocation_reason=data["reason"],
            revoked_at=now,
            revoked_by=actor.subject,
        )
    return put(state, "certificate", data["id"], record)


def view(state: dict[str, Any], actor: Identity, now: str) -> dict[str, Any]:
    if not set(actor.roles) & {"operator", "reviewer", "auditor"}:
        raise DomainError("Role not authorized", 403)
    return {
        "certificates": [
            {k: v for k, v in c.items() if k not in {"csr_pem", "certificate_pem", "ca_pem"}}
            | {"expired": stamp(c["not_after"]) <= stamp(now) if c.get("not_after") else False}
            for c in state.get("certificate", {}).values()
        ],
        "scope": "disposable_local_private_ca",
        "revocation": "renewal_blocked_and_crl_exported_relying_services_must_enforce",
    }
