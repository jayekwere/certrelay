from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography import x509

from app.common import DEMO_IDENTITIES, DomainError, Identity, clock
from app.domain import Approval, CertificateRequest, Ref, Revocation, dispatch, view
from app.pki import Authority, csr, live_exchange, new_key, private_write, validate_csr

OP = DEMO_IDENTITIES["demo-operator"]
REVIEW = DEMO_IDENTITIES["demo-reviewer"]


def test_restricted_csr_identity_and_key_validation() -> None:
    key = new_key()
    pem = csr("localhost", key)
    assert validate_csr(pem, "localhost").is_signature_valid
    for bad in ["not-a-csr", "-----BEGIN PRIVATE KEY-----"]:
        with pytest.raises(DomainError):
            validate_csr(bad, "localhost")
    with pytest.raises(DomainError):
        validate_csr(pem, "api.certrelay.test")
    with pytest.raises(DomainError):
        csr("attacker.invalid", key)


def test_real_issuance_revocation_renewal_and_tenant(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PKI_ROOT", str(tmp_path / "pki"))
    state: dict[str, Any] = {}
    now = clock()
    key = new_key()
    request = CertificateRequest(
        id="api",
        name="localhost",
        usage="server",
        csr_pem=csr("localhost", key),
        lifetime_minutes=10,
    )
    record = dispatch(state, OP, "request-certificate", request, now)
    same = Identity(tenant="alder", subject=OP.subject, roles=["reviewer"])
    with pytest.raises(DomainError):
        dispatch(
            state,
            same,
            "approve-certificate",
            Approval(id="api", request_sha256=record["request_sha256"]),
            now,
        )
    with pytest.raises(DomainError):
        dispatch(
            state, REVIEW, "approve-certificate", Approval(id="api", request_sha256="a" * 64), now
        )
    dispatch(
        state,
        REVIEW,
        "approve-certificate",
        Approval(id="api", request_sha256=record["request_sha256"]),
        now,
    )
    issued = dispatch(state, OP, "issue-certificate", Ref(id="api"), now)
    assert x509.load_pem_x509_certificate(issued["certificate_pem"].encode()).serial_number == int(
        issued["serial"]
    )
    renewed = dispatch(
        state,
        OP,
        "request-certificate",
        request.model_copy(
            update={"id": "renewed", "renews": "api", "csr_pem": csr("localhost", new_key())}
        ),
        now,
    )
    assert renewed["status"] == "pending"
    dispatch(
        state, REVIEW, "revoke-certificate", Revocation(id="api", reason="key-compromise"), now
    )
    with pytest.raises(DomainError):
        dispatch(
            state,
            OP,
            "request-certificate",
            request.model_copy(update={"id": "blocked", "renews": "api"}),
            now,
        )
    dispatch(
        state,
        REVIEW,
        "approve-certificate",
        Approval(id="renewed", request_sha256=renewed["request_sha256"]),
        now,
    )
    with pytest.raises(DomainError):
        dispatch(state, OP, "issue-certificate", Ref(id="renewed"), now)
    exported = dispatch(
        state, REVIEW, "export-crl", __import__("app.common", fromlist=["Contract"]).Contract(), now
    )
    crl = x509.load_pem_x509_crl(exported["crl_pem"].encode())
    assert crl.get_revoked_certificate_by_serial_number(int(issued["serial"])) is not None
    assert (tmp_path / "pki/alder/ca.key").stat().st_mode & 0o077 == 0
    assert "csr_pem" not in view(state, REVIEW, now)["certificates"][0]
    with pytest.raises(DomainError):
        view(state, DEMO_IDENTITIES["demo-support"], now)


def test_actual_tls_faults_rotation_and_crl(tmp_path: Path) -> None:
    result = live_exchange(tmp_path / "tls")
    assert len(result["checks"]) == 10 and all(result["checks"].values())


def test_ca_file_permissions_and_incomplete_state(tmp_path: Path) -> None:
    ca = Authority(tmp_path / "ca")
    ca.root.joinpath("ca.key").chmod(0o644)
    with pytest.raises(ValueError):
        Authority(ca.root)
    ca.root.joinpath("ca.key").chmod(0o600)
    ca.root.joinpath("ca.pem").unlink()
    with pytest.raises(ValueError):
        Authority(ca.root)
    file = tmp_path / "private"
    private_write(file, b"test")
    with pytest.raises(FileExistsError):
        private_write(file, b"other")


def test_successful_renewal_requires_new_independent_approval(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PKI_ROOT", str(tmp_path / "pki"))
    state: dict[str, Any] = {}
    now = clock()
    request = CertificateRequest(
        id="original",
        name="localhost",
        usage="server",
        csr_pem=csr("localhost", new_key()),
        lifetime_minutes=10,
    )
    first = dispatch(state, OP, "request-certificate", request, now)
    dispatch(
        state,
        REVIEW,
        "approve-certificate",
        Approval(id="original", request_sha256=first["request_sha256"]),
        now,
    )
    issued = dispatch(state, OP, "issue-certificate", Ref(id="original"), now)
    renewed = dispatch(
        state,
        OP,
        "request-certificate",
        request.model_copy(
            update={
                "id": "replacement",
                "renews": "original",
                "csr_pem": csr("localhost", new_key()),
            }
        ),
        now,
    )
    with pytest.raises(DomainError):
        dispatch(state, OP, "issue-certificate", Ref(id="replacement"), now)
    dispatch(
        state,
        REVIEW,
        "approve-certificate",
        Approval(id="replacement", request_sha256=renewed["request_sha256"]),
        now,
    )
    replacement = dispatch(state, OP, "issue-certificate", Ref(id="replacement"), now)
    assert replacement["fingerprint_sha256"] != issued["fingerprint_sha256"]
    assert replacement["serial"] != issued["serial"] and replacement["renews"] == "original"
