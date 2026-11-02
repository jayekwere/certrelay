# API and operation contracts

`GET /health` reports local readiness. `GET /api/scenario` is public only in explicit synthetic demo mode. `POST /api/actions` accepts `{ "action": "operation-name", "data": {}, "key": "unique-command-key" }` and requires a bearer identity. Exact action payloads are in `schemas/contracts.json`. Keys bind the exact actor and command within a tenant. `GET /api/state` returns the role-scoped domain view and records a read receipt. `GET /api/evidence` requires reviewer role and verifies the tenant-local audit chain.

Errors return a sanitized `error` field. Authentication failure is 401, role/scope denial 403, missing record 404, stale or conflicting state 409, oversized body 413, unsupported content type 415 and schema violation 422. The body cap is 256 KiB. State is bounded; capacity exhaustion returns 429.

Configured mode: write a mode-600 JSON identity file mapping random tokens of at least 32 characters to `{ "tenant": "alder", "subject": "alex", "roles": ["operator"] }`. Set `IDENTITY_FILE` and run `python -m app.cli serve` without `--demo`. No public demo credentials are loaded, and the scenario workbench is disabled. Use the authenticated API directly. Keep the service on loopback; a supported production ingress is not supplied.
