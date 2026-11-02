# CertRelay threat model

## Assets and boundaries

Protect server-owned bearer identities, tenant records, approval decisions, evidence provenance and private local state. Treat every API payload, source export, rendered field, record identifier and browser origin as untrusted. Identity mappings, the operating system account, deployment code and private state directory are trusted.

## Domain threats

A CSR must not request arbitrary identities, CA privileges or usages. Approvers must be independent of requesters. A pending renewal must become unusable if its original certificate is revoked. Relying services must verify both trust and authorized identity, and enforce a current CRL rather than treating a revocation database flag as network enforcement.

## Shared controls

Authentication maps opaque bearer tokens to server-owned tenant, subject and roles. Tenant identifiers are never accepted from operation bodies. Every lookup is scoped by the authenticated tenant transaction. Independent approval compares subject identifiers, not token strings or role names. Exact schema validation rejects extra fields and loose boolean coercion. Idempotency binds the full command and actor; conflicting key reuse fails. Request bytes are bounded before domain processing. Unknown origins and hosts are rejected; credentials are not stored in browser persistent storage. CSP denies inline scripts and framing; rendering uses textContent. External collectors do not follow redirects or inherit environment proxies where implemented.

## Residual risk

Private files and SQLite are not a substitute for encryption, centralized identity, distributed rate limiting, secure deployment or independent evidence storage. A host administrator can alter data and recompute the unauthenticated audit chain. Denied and invalid requests are returned as sanitized errors; they are not a complete intrusion-detection event stream. Local demo identities intentionally represent different synthetic subjects, not independently operated human accounts. Availability under malicious connection pressure, production scale and external account permissions are outside local acceptance.
