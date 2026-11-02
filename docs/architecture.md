# CertRelay architecture

The issuing API accepts P-256 CSRs with exactly one allowlisted lab DNS identity and no extra extensions. It verifies the CSR signature and requires independent approval bound to its digest. Private client keys stay outside the API; the sample contains only a public CSR whose original private key was discarded. Issuance reconstructs safe extensions, uses cryptographic random serials and checks CA validity. Renewal retains holder, identity and usage checks and rechecks the original certificate at issuance after approval. CA keys live in tenant-specific private directories outside committed files. The separate TLS lab creates disposable keys and uses native Python/OpenSSL handshakes, strict trust validation, mutual authentication, identity authorization, leaf replacement, expiry and a loaded CRL.

## Domain sequence

Public CSR --> Restricted identity policy --> Independent digest approval --> Local CA issuance --> Renewal or revocation --> CRL enforcement

## Consistency and recovery

`app/domain.py` owns explicit schemas and domain transitions. `app/service.py` validates input and commits state, audit entry and idempotency receipt in one SQLite transaction with `BEGIN IMMEDIATE`. `app/api.py` authenticates server-owned identities, limits request bytes and exposes scoped operations. `app/cli.py` executes the committed scenario against the same service. `web/` validates the scenario contract and renders real API results without HTML interpolation.

A process crash before commit rolls back domain state and receipts. Local filesystem effects in the certificate authority are separate from SQLite and partial CA initialization fails closed. Container state is disposable. Persistence, backups, independent audit checkpoints and external identity lifecycle are deployment responsibilities.

## Explicit scope

Disposable local private CA only. No ACME server, public CA, cloud certificate manager, Kubernetes cert-manager or HSM integration is claimed. Issuance validity and cryptographic randomness use the real clock, so output bytes vary. The policy workflow and standalone TLS fault lab use separate disposable authorities and demonstrate distinct boundaries. Revocation blocks renewal and exports a CRL; relying services must load it. The TLS lab verifies rejection at a new handshake and does not terminate existing sessions. The rotation check verifies a changed fingerprint and a new successful connection, not uninterrupted production availability. Private CA keys are owner-only files, not encrypted or hardware-protected. Partial CA initialization fails closed and requires operator recovery.

Renewal is an explicit reviewed lifecycle, not a background unattended scheduler. A new public CSR and independent approval are required before signing a replacement. Tests verify a changed certificate fingerprint and serial, and block renewal after the original certificate has been revoked.
