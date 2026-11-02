from __future__ import annotations

import os
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.common import DomainError

ALLOWED_NAMES = {
    "localhost",
    "api.certrelay.test",
    "database.certrelay.test",
    "operator.certrelay.test",
}


def private_write(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(data)


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def csr(name: str, key: ec.EllipticCurvePrivateKey) -> str:
    if name not in ALLOWED_NAMES:
        raise DomainError("Certificate identity outside local lab allowlist", 422)
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )


def validate_csr(pem: str, name: str) -> x509.CertificateSigningRequest:
    try:
        request = x509.load_pem_x509_csr(pem.encode())
        names = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        public = request.public_key()
        if (
            not request.is_signature_valid
            or not isinstance(public, ec.EllipticCurvePublicKey)
            or public.curve.name != "secp256r1"
            or list(names) != [x509.DNSName(name)]
            or name not in ALLOWED_NAMES
        ):
            raise ValueError("CSR identity or key rejected")
        if len(list(request.extensions)) != 1:
            raise ValueError("Unsupported CSR extensions")
        return request
    except (ValueError, x509.ExtensionNotFound, x509.DuplicateExtension) as exc:
        raise DomainError("CSR violates the restricted local issuance policy", 422) from exc


class Authority:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink():
            raise ValueError("PKI directory cannot be a symlink")
        root.chmod(0o700)
        self.root = root
        key_file, cert_file = root / "ca.key", root / "ca.pem"
        if key_file.exists() != cert_file.exists():
            raise ValueError("Incomplete CA state requires operator recovery")
        if not key_file.exists():
            key = new_key()
            now = datetime.now(UTC)
            name = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "CertRelay disposable lab CA")]
            )
            certificate = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
            )
            private_write(key_file, key_bytes(key))
            private_write(cert_file, certificate.public_bytes(serialization.Encoding.PEM))
        for file in [key_file, cert_file]:
            if file.is_symlink() or file.stat().st_mode & 0o077:
                raise ValueError("CA files must be private regular files")
        loaded = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            raise ValueError("Unsupported CA key")
        self.key = loaded
        self.cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        if self.key.public_key().public_numbers() != self.cert.public_key().public_numbers():  # type: ignore[union-attr]
            raise ValueError("CA key and certificate mismatch")

    def issue(
        self, pem: str, name: str, usage: str, minutes: int = 10, *, expired: bool = False
    ) -> x509.Certificate:
        request = validate_csr(pem, name)
        now = datetime.now(UTC)
        if self.cert.not_valid_after_utc <= now + timedelta(minutes=minutes):
            raise DomainError("CA renewal is required before issuing this certificate")
        before, after = (
            (now - timedelta(minutes=20), now - timedelta(minutes=10))
            if expired
            else (now - timedelta(seconds=30), now + timedelta(minutes=minutes))
        )
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(self.cert.subject)
            .public_key(request.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(before)
            .not_valid_after(after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(request.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if usage == "server"
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )

    def crl(self, serials: list[int]) -> bytes:
        now = datetime.now(UTC)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(now - timedelta(seconds=1))
            .next_update(now + timedelta(minutes=10))
        )
        for serial in serials:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
            )
        return builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def authority(tenant: str) -> Authority:
    return Authority(Path(os.environ.get("PKI_ROOT", "artifacts/pki")) / tenant)


def live_exchange(root: Path) -> dict[str, Any]:
    ca = Authority(root / "ca")
    other = Authority(root / "untrusted")
    keys = {
        name: new_key()
        for name in ["server", "rotated", "client", "expired", "untrusted", "wrong-client"]
    }
    certificates = {
        "server": ca.issue(csr("localhost", keys["server"]), "localhost", "server"),
        "rotated": ca.issue(csr("localhost", keys["rotated"]), "localhost", "server"),
        "client": ca.issue(
            csr("operator.certrelay.test", keys["client"]), "operator.certrelay.test", "client"
        ),
        "expired": ca.issue(csr("localhost", keys["expired"]), "localhost", "server", expired=True),
        "untrusted": other.issue(
            csr("operator.certrelay.test", keys["untrusted"]), "operator.certrelay.test", "client"
        ),
        "wrong-client": ca.issue(
            csr("database.certrelay.test", keys["wrong-client"]),
            "database.certrelay.test",
            "client",
        ),
    }
    for name, key in keys.items():
        private_write(root / f"{name}.key", key_bytes(key))
        private_write(
            root / f"{name}.pem", certificates[name].public_bytes(serialization.Encoding.PEM)
        )
    trust_file = root / "trust.pem"
    trust_file.write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM) + ca.crl([]))
    trust_file.chmod(0o600)

    def server_context(name: str, revoked: bool = False) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(root / f"{name}.pem", root / f"{name}.key")
        bundle = root / ("revoked-trust.pem" if revoked else "trust.pem")
        if revoked:
            bundle.write_bytes(
                ca.cert.public_bytes(serialization.Encoding.PEM)
                + ca.crl([certificates["client"].serial_number])
            )
            bundle.chmod(0o600)
        context.load_verify_locations(bundle)
        context.verify_mode = ssl.CERT_REQUIRED
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        return context

    active = server_context("server")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    stopping = threading.Event()

    def serve() -> None:
        while not stopping.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                connection.settimeout(2)
                with active.wrap_socket(connection, server_side=True) as secured:
                    peer_bytes = secured.getpeercert(binary_form=True)
                    assert peer_bytes is not None
                    peer = x509.load_der_x509_certificate(peer_bytes)
                    names = peer.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    ).value.get_values_for_type(x509.DNSName)
                    if names != ["operator.certrelay.test"]:
                        secured.sendall(b"DENIED")
                    else:
                        secured.recv(4)
                        secured.sendall(b"PONG")
            except (OSError, ValueError):
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    diagnostics: list[dict[str, Any]] = []

    def probe(
        client: str | None = "client", hostname: str = "localhost", trusted: bool = True
    ) -> bool:
        context = ssl.create_default_context(
            cafile=str((root / "ca/ca.pem") if trusted else (root / "untrusted/ca.pem"))
        )
        if client:
            context.load_cert_chain(root / f"{client}.pem", root / f"{client}.key")
        try:
            with (
                socket.create_connection(listener.getsockname(), timeout=2) as raw,
                context.wrap_socket(raw, server_hostname=hostname) as secured,
            ):
                secured.sendall(b"PING")
                return secured.recv(8) == b"PONG"
        except OSError as error:
            diagnostics.append(
                {
                    "type": type(error).__name__,
                    "verify_code": getattr(error, "verify_code", None),
                    "reason": getattr(error, "verify_message", None),
                }
            )
            return False

    try:
        checks = {
            "trusted_mutual_tls": probe(),
            "missing_client_rejected": not probe(None),
            "untrusted_client_rejected": not probe("untrusted"),
            "unauthorized_identity_rejected": not probe("wrong-client"),
            "wrong_hostname_rejected": not probe(hostname="wrong.certrelay.test"),
            "untrusted_server_rejected": not probe(trusted=False),
        }
        active = server_context("rotated")
        checks["rotated_connection_succeeds"] = probe()
        checks["leaf_fingerprint_changed"] = certificates["server"].fingerprint(
            hashes.SHA256()
        ) != certificates["rotated"].fingerprint(hashes.SHA256())
        active = server_context("expired")
        checks["expired_server_rejected"] = not probe()
        active = server_context("rotated", revoked=True)
        checks["revoked_client_rejected_new_handshake"] = not probe()
        if not all(checks.values()):
            raise AssertionError(f"TLS evidence failed: {checks}; observations: {diagnostics}")
        return {
            "transport": "actual-loopback-tls",
            "checks": checks,
            "revocation": "CRL_enforced_at_new_handshake",
            "existing_sessions": "not_terminated_by_certificate_revocation",
        }
    finally:
        stopping.set()
        listener.close()
        thread.join(timeout=3)
