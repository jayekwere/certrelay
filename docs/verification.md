# Verification and evidence

The local CLI scenario invokes the same domain service as the API. Expected denials are asserted, not substituted with canned responses. Public sample output is captured by executing it against the committed synthetic inputs. Python tests include authorization, schema boundaries, tenant separation, independent subjects, idempotency conflicts, concurrent replay and audit tampering. Domain-specific cases exercise evidence fidelity, stale decisions and expiry. Browser tests use the actual HTTP server without mocked responses and check the narrow mobile layout. The screenshot is captured from that run.

Python coverage includes the entire `app` package, statements and branches, with an 80% minimum gate. CLI startup and optional native collectors remain in the denominator. Node coverage measures the imported TypeScript scenario contract and reference resolver only. It does not measure the browser application or Python service. Browser and Docker results are separate checks, not added to either coverage percentage.

The restricted Docker smoke check verifies a non-root UID, HTTP response and content security policy under a read-only root with dropped capabilities. A separate container command runs the complete CLI demonstration with external networking disabled. Dependencies require network during setup/build. Hosted CI uses SHA-pinned actions, contents-read permission and disabled checkout credential persistence. Python lockfiles contain hashes and Node versions are locked. Runtime dependency advisory checks are performed separately for both languages.

`docs/local-verification.json` records measured local results. `docs/hosted-verification.json`, after publication, identifies the exact hosted commit and Verify run. Green CI applies to that revision only and is not a guarantee of external account permissions, production scalability or absence of all vulnerabilities.

Certificate signatures, serials, validity times, CRLs and derived receipt hashes vary. CI verifies the parsed certificate, revoked serial, expected denial and all ten real TLS checks with `scripts/verify-demo.py`, rather than comparing cryptographic output bytes to an old sample. The sample CSR is public fixture material; its generating private key is not stored. CA private keys never appear in CI artifacts.

[Hosted Verify run 41370935453](https://github.com/jayekwere/certrelay/actions/runs/41370935453) passed at `34d61a050ece08a799dc3e5360d3d24b1e575678`. Exact jobs, steps and artifact digests are recorded in [the hosted receipt](hosted-verification.json).

Public CI artifacts use an explicit file allowlist and reject private-key markers. Browser state and disposable CA keys are kept in the ignored `.local` directory and are excluded from uploaded evidence. Earlier certificate-lab artifacts containing disposable private CA material were withdrawn. No account credential or externally trusted key was involved.

[Hosted Verify run 41371629929](https://github.com/jayekwere/certrelay/actions/runs/41371629929) passed at `c5dfdddee778adee4c63d3581598039e71c8c96a`. Exact jobs, steps and artifact digests are recorded in [the hosted receipt](hosted-verification.json).
