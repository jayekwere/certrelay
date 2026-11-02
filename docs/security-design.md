# Security design decisions

- Keep state and replay receipts transactional; reject conflicting command keys.
- Derive tenant and roles exclusively from trusted identities.
- Compare independent reviewers by subject, including when one subject holds multiple roles.
- Preserve missing evidence, stale observations and unknown permissions as distinct outcomes.
- Scope exports and retain provenance instead of asserting external truth from a digest.
- Use private local files and exclusive writes for generated material.
- Keep cloud and third-party writes outside these demos.
- Pin CI actions by commit, limit workflow permissions to contents read and avoid persisted checkout credentials.
- Hash-lock Python dependencies and lock exact Node dependencies.

A CSR must not request arbitrary identities, CA privileges or usages. Approvers must be independent of requesters. A pending renewal must become unusable if its original certificate is revoked. Relying services must verify both trust and authorized identity, and enforce a current CRL rather than treating a revocation database flag as network enforcement.
