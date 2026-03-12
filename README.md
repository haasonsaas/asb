# ASB

ASB is an agents-first secret broker and control plane written in Go.

It is not a generic secret-path reader. Instead, it binds secret access to:

- an attested workload
- a single agent run
- a trusted tool
- an explicit capability
- an explicit resource
- a short-lived delivery mode

The current codebase implements a runnable v1 broker baseline from the consolidated spec:

- session creation from Kubernetes projected service account JWTs
- signed internal session tokens
- signed delegation validation
- policy evaluation and tool trust checks
- grant issuance and approval gating
- GitHub proxy handle issuance, downstream proxy execution, and GitHub App token exchange
- Vault-backed Postgres dynamic credential brokering
- browser relay registration and single-use unwrap/fill responses
- JSON/HTTP and ConnectRPC transports
- in-memory, Postgres, and Redis-backed runtime/storage components
- migration and cleanup worker binaries
- GitHub Actions CI

## Status

This repository is a working implementation baseline, not a finished production deployment.

What is implemented:

- `CreateSession`, `RequestGrant`, `ApproveGrant`, `DenyGrant`, `RevokeGrant`, `RevokeSession`
- `/v1/proxy/github/rest`
- browser relay registration and artifact unwrap APIs
- ConnectRPC service definitions and generated stubs
- GitHub HTTP proxy executor with static-token and GitHub App auth support
- Vault HTTP client and DB connector
- browser connector with selector-map-based fill data
- Postgres repository and Redis runtime-state store
- schema migration runner and worker cleanup loop
- GitHub Actions CI for formatting, proto regeneration, vet, and tests
- unit and service-level tests across the major flows

What is still intentionally lightweight:

- no full production approval callback transport yet
- no KMS-backed artifact encryption yet
- no frontend admin UI or browser extension package in this repo yet

## Repository Layout

```text
cmd/
  asb-api/              API entrypoint
  asb-migrate/          Migration CLI
  asb-worker/           Cleanup worker
db/
  migrations/           SQL schema
internal/
  bootstrap/            Shared command bootstrap wiring
  api/
    connectapi/         ConnectRPC transport
    httpapi/            JSON/HTTP transport
  migrate/              Migration runner
  worker/               Cleanup runner
  app/                  Core broker service
  audit/                Audit sinks
  authn/                Attestation and delegation validation
  authz/                Policy engine and tool registry
  connectors/           GitHub, Vault DB, browser, resolver
  crypto/               Session JWT support
  delivery/             Proxy and wrapped-secret delivery adapters
  store/                Memory, Postgres, Redis implementations
proto/
  asb/v1/               Proto and generated code
```

## Core Concepts

### Sessions

Sessions are created from workload attestation and become the root identity for a run.

The current implementation:

- verifies Kubernetes projected SA JWTs
- normalizes workload identity
- creates a persisted session record
- issues an Ed25519-signed internal session token
- binds session decisions to `tenant_id`, `agent_id`, `run_id`, `tool_context`, and `workload_hash`

### Grants

Grants are narrow authorizations for one capability, one resource, one delivery mode, and one tool.

The service enforces:

- capability-policy lookup
- tool registry checks
- delivery-mode allowlists
- TTL clamping
- delegation resource filters
- approval gating for high-risk flows

### Delivery Modes

- `proxy`: the broker executes the downstream call and the agent only receives a handle
- `wrapped_secret`: the broker returns a short-lived artifact reference for trusted runtimes

Minted tokens remain modeled in the domain, but are not enabled in the runtime wiring yet.

## Transports

Two transports are exposed by `cmd/asb-api`:

- JSON/HTTP under `/v1/...`
- ConnectRPC under `/asb.v1.BrokerService/...`

### JSON Endpoints

- `POST /v1/sessions`
- `POST /v1/grants`
- `POST /v1/approvals/{approval_id}:approve`
- `POST /v1/approvals/{approval_id}:deny`
- `POST /v1/grants/{grant_id}:revoke`
- `POST /v1/sessions/{session_id}:revoke`
- `POST /v1/proxy/github/rest`
- `POST /v1/browser/relay-sessions`
- `POST /v1/artifacts/{artifact_id}:unwrap`

### ConnectRPC Methods

See `proto/asb/v1/broker.proto` for the complete API contract.

## Connectors

### GitHub

The GitHub connector issues proxy handles only, and the executor supports either a static token or a GitHub App installation-token flow.

Implemented allowlisted operations:

- `pull_request_metadata`
- `pull_request_files`
- `repository_metadata`
- `repository_issues`

The executor clamps pagination, looks up or mints repo-scoped access tokens, and relies on per-handle runtime budgets stored in memory or Redis.

### Vault DB

The Vault DB connector:

- validates read-only roles
- fetches dynamic credentials from Vault
- renders a DSN from a configured template
- returns wrapped-secret artifacts
- revokes Vault leases when grants or sessions are revoked

### Browser

The browser connector:

- validates exact origins
- requires selector maps per origin
- returns wrapped browser credential artifacts
- feeds unwrap responses that contain explicit field selector/value pairs
- never auto-submits

## Storage

### In-Memory

Default for local development when no persistence env vars are provided.

### Postgres

If `ASB_POSTGRES_DSN` is set, `cmd/asb-api` uses the Postgres repository implementation.

Schema changes are applied with `cmd/asb-migrate`.

Current migration files:

- `db/migrations/0001_init.sql`

### Redis

If `ASB_REDIS_ADDR` is set, `cmd/asb-api` uses the Redis runtime-state store for:

- proxy handle budgets
- browser relay session state

## Worker

`cmd/asb-worker` runs cleanup passes over expired approvals, grants, sessions, and artifacts.

The current worker:

- expires stale approval records
- expires grants on TTL and session expiry
- triggers downstream revoke best effort for expiring grants
- marks artifacts expired or revoked as state changes happen

## Configuration

### Required for API Startup

- `ASB_K8S_ISSUER`
- `ASB_K8S_PUBLIC_KEY_FILE`

### Optional

- `ASB_K8S_AUDIENCE`
- `ASB_ADDR`
- `ASB_DEV_TENANT_ID`
- `ASB_POSTGRES_DSN`
- `ASB_REDIS_ADDR`
- `ASB_REDIS_PASSWORD`
- `ASB_GITHUB_TOKEN`
- `ASB_GITHUB_API_BASE_URL`
- `ASB_GITHUB_APP_ID`
- `ASB_GITHUB_APP_PRIVATE_KEY_FILE`
- `ASB_GITHUB_APP_PERMISSIONS_JSON`
- `ASB_DELEGATION_ISSUER`
- `ASB_DELEGATION_PUBLIC_KEY_FILE`
- `ASB_SESSION_SIGNING_PRIVATE_KEY_FILE`

### Optional Browser Demo Config

- `ASB_BROWSER_ORIGIN`
- `ASB_BROWSER_USERNAME`
- `ASB_BROWSER_PASSWORD`
- `ASB_BROWSER_SELECTOR_USERNAME`
- `ASB_BROWSER_SELECTOR_PASSWORD`

### Optional Vault Demo Config

- `ASB_VAULT_ADDR`
- `ASB_VAULT_TOKEN`
- `ASB_VAULT_NAMESPACE`
- `ASB_VAULT_ROLE`
- `ASB_VAULT_DSN_TEMPLATE`

## Local Development

### Commands

```bash
make proto
make fmt
make vet
make test
make migrate
make run-api
make run-worker
```

### Example Startup

```bash
export ASB_K8S_ISSUER="https://cluster.example"
export ASB_K8S_PUBLIC_KEY_FILE="./dev/keys/k8s-sa.pub"
export ASB_GITHUB_TOKEN="ghp_..."
make run-api
```

### Health Check

```bash
curl http://localhost:8080/healthz
```

## Testing

The project is developed test-first around the critical broker behavior:

- attestation validation
- signed delegation validation
- GitHub App token issuance and caching
- policy evaluation
- grant approval and issuance
- session and grant revocation
- cleanup worker expiry handling
- GitHub proxy execution
- browser relay registration and unwrap
- Vault credential issue and revoke
- Postgres repository persistence
- Redis runtime budget and relay state
- JSON/HTTP and ConnectRPC adapters

Run everything with:

```bash
make test
```

CI runs the same core checks on GitHub:

- `make fmt`
- `make proto`
- `go vet ./...`
- `make test`

## Security Notes

- session tokens are short-lived and signed with Ed25519
- browser unwrap is single-use
- browser fill responses are explicit and selector-bound
- GitHub proxy execution is operation-allowlisted
- proxy runtime budgets are enforced per handle
- grant decisions are tied to trusted tools and explicit resources
- audit events are emitted from the service layer

## Next Steps

- encrypt wrapped artifacts at rest with KMS-backed envelopes
- add approval callback signing and replay protection
- ship a browser extension package for the relay runtime
- add stronger runtime binding for future minted-token delivery
