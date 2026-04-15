# ASB

ASB is an agents-first secret broker written in Go.

It does not treat secret access as "read a path and hand back a credential."
Instead, it turns secret access into a scoped, auditable execution decision tied to:

- an attested workload
- a single agent run
- a trusted tool
- an explicit capability
- an explicit resource
- a short-lived delivery mode

ASB exists for cases where an agent should not receive broad standing credentials, and where access must be constrained to a specific operation, runtime, and approval path.

The current repository is a working v1 implementation baseline. It can create attested sessions, issue narrow grants, mediate downstream access through proxy or wrapped-artifact delivery, and persist runtime state across in-memory, Postgres, and Redis-backed components.

It is not yet a full production deployment.

## What makes ASB different

Traditional secret systems answer:
> "Can this principal read this secret?"

ASB answers:
> "Can this specific agent run, using this specific trusted tool, perform this specific action on this specific resource right now, and how should that access be delivered?"

ASB is not a generic secret-path reader and does not hand broad credentials directly to agents. It is a policy and delivery system for agent-execution-bound access.

## Core control model

ASB has three core jobs:

1. **Authenticate the workload and bind a session to a single agent run.**
   Sessions are created from Kubernetes projected service account JWTs. The broker verifies the token, normalizes a workload identity, and issues an Ed25519-signed internal session token bound to `tenant_id`, `agent_id`, `run_id`, `tool_context`, and `workload_hash`.

2. **Authorize a narrow grant for a specific tool, capability, resource, and delivery mode.**
   The service enforces capability-policy lookup, tool registry and trust-tag checks, delivery-mode allowlists, TTL clamping, delegation resource filters, and approval gating for high-risk flows. Grants are never broader than the intersection of policy, delegation, and tool trust.

3. **Mediate downstream access through proxy execution or wrapped artifacts.**
   The broker either executes the downstream call itself (proxy mode, where the agent only receives an opaque handle) or returns a short-lived, single-use artifact reference for trusted runtimes (wrapped-secret mode). The agent never touches the raw credential in the proxy path.

## Why ASB exists

Most infrastructure already has a secret store. The gap is not storage — it is mediation.

Vault answers "who can read this path." SPIFFE/SPIRE answers "what is this workload's identity." GitHub App tokens answer "what can this installation do." None of them answer "should this specific agent run, using this specific trusted tool, be allowed to perform this specific action on this specific resource right now, and how should that access be delivered?"

ASB sits between the agent and the downstream system. It binds access to agent execution context, not just identity. It constrains delivery mode, operation scope, and runtime budget. It makes secret access an auditable execution decision rather than a credential lookup.

## Current capabilities

ASB currently supports:

- workload-attested session creation from Kubernetes projected service account JWTs
- signed internal session tokens (Ed25519) for broker-authenticated follow-on requests
- signed delegation validation with per-capability resource filtering
- narrow grant issuance with policy checks, tool trust checks, TTL clamping, and approval gating
- GitHub proxy access through allowlisted operations, including GitHub App installation-token exchange
- Vault-backed dynamic Postgres credential brokering delivered as wrapped artifacts
- browser relay registration with single-use unwrap responses and selector-bound fill data
- shared notifications-service delivery for pending approval events
- JSON/HTTP and ConnectRPC transports
- in-memory, Postgres, and Redis-backed storage and runtime components
- migration and cleanup worker binaries
- CI and service-level test coverage across the major flows

### Intentionally simplified in v1

- no full production approval callback transport yet (pending approvals can be emitted through the shared notifications service, but approver routing is still runtime-configured)
- no KMS-backed artifact encryption yet (artifacts are stored, but not envelope-encrypted at rest)
- no frontend admin UI or browser extension package in this repo yet
- minted-token delivery is modeled in the domain but not enabled in runtime wiring

### Required before production

- artifact encryption at rest with KMS-backed envelopes
- signed approval callbacks with replay protection
- hardened key management and rotation for session signing and delegation verification
- HA deployment guidance and failure-mode testing
- connector-specific security review and operational limits
- end-to-end audit pipeline durability guarantees
- browser extension packaging and distribution

## Threat model assumptions

- workloads are authenticated through projected Kubernetes service account JWTs
- trusted tools are registered and policy-checked before grants can be issued
- grants are narrow in scope and short in lifetime
- wrapped artifacts are intended for trusted runtimes only
- downstream access should be revocable on session or grant expiry
- proxy execution is operation-allowlisted and budget-constrained
- ASB reduces standing credential exposure, but does not make a compromised trusted runtime harmless

## Connectors

### GitHub

The GitHub connector does not hand the agent a token. It issues an opaque proxy handle, and the broker executes allowlisted GitHub API operations on behalf of the agent.

The handle encodes operation scope and is validated by the broker on every use. Per-handle runtime budgets (max concurrent requests, max total requests, max bytes) are enforced in-memory or via Redis.

Implemented allowlisted operations:

- `pull_request_metadata`
- `pull_request_files`
- `repository_metadata`
- `repository_issues`

The executor supports two token sources: a static token for development, or a GitHub App installation-token flow that caches repo-to-installation mappings and mints repo-scoped tokens with minimal permissions (`contents:read`, `issues:read`, `pull_requests:read`).

### Vault DB

The Vault DB connector brokers short-lived Postgres credentials through HashiCorp Vault's database secrets engine.

- validates read-only roles (role names must end with `_ro` — this is static config, enforced by the connector)
- fetches dynamic credentials from Vault
- renders a DSN from a configured template
- returns wrapped-secret artifacts with the Vault lease ID in metadata for revocation tracking
- revokes Vault leases when grants or sessions are revoked

### Browser

The browser connector returns wrapped credential artifacts with explicit field-level fill instructions.

- validates exact origin URLs
- requires a selector map per origin (CSS selectors for each credential field)
- unwrap returns explicit field selector/value pairs only — the broker never returns a general browser credential blob
- single-use unwrap enforced at the artifact level
- never auto-submits

### Connector resolution

A static resolver routes capability and resource kind to the appropriate connector. Each connector validates its own resource descriptors independently.

## Delivery modes

- **`proxy`**: the broker executes the downstream call and the agent only receives an opaque handle. The agent never sees the credential. Budget-enforced per handle.
- **`wrapped_secret`**: the broker returns a short-lived, single-use artifact reference for trusted runtimes. The artifact is bound to recipient identity (session, key, origin, tab).
- **`minted_token`** *(planned, not runtime-enabled)*: direct short-lived token issuance for cases where proxy is impractical. Modeled in the domain types but currently rejected with an explicit not-implemented error until runtime support lands.

## Storage

### Postgres

Primary persistence for sessions, grants, approvals, artifacts, and audit events. If `ASB_POSTGRES_DSN` is set, `cmd/asb-api` uses the Postgres repository. Schema managed via `cmd/asb-migrate`.

### Redis

Runtime state only, not source-of-truth persistence. Used for proxy handle budgets and browser relay session state when `ASB_REDIS_ADDR` is set. Keys are set with automatic expiry. Watch-based transactions enforce concurrent budget limits. No durability guarantees — state is reconstructable from Postgres.

### In-memory

Default for local development when no persistence env vars are provided. Thread-safe via `sync.RWMutex`. Full repository interface with deep cloning on read/write.

## Transports

Two transports are exposed by `cmd/asb-api`:

- JSON/HTTP under `/v1/...`
- ConnectRPC under `/asb.v1.BrokerService/...`

### JSON endpoints

```
POST /v1/sessions                          CreateSession
POST /v1/grants                            RequestGrant
POST /v1/approvals/{approval_id}:approve   ApproveGrant
POST /v1/approvals/{approval_id}:deny      DenyGrant
POST /v1/grants/{grant_id}:revoke          RevokeGrant
POST /v1/sessions/{session_id}:revoke      RevokeSession
POST /v1/proxy/github/rest                 ExecuteGitHubProxy
POST /v1/browser/relay-sessions            RegisterBrowserRelay
POST /v1/artifacts/{artifact_id}:unwrap    UnwrapArtifact
```

### ConnectRPC

See `proto/asb/v1/broker.proto` for the complete API contract.

## Repository layout

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

## Worker

`cmd/asb-worker` runs periodic cleanup passes over expired state:

- expires stale approval records
- expires grants on TTL and session expiry
- triggers downstream connector revocation (best-effort) for expiring grants
- marks artifacts expired or revoked as state changes propagate

Flags: `-interval` (default 30s), `-limit` (default 100 per pass), `-once` (single run then exit).

## Configuration

### Required for API startup

| Variable | Purpose |
|----------|---------|
| `ASB_K8S_ISSUER` | Expected issuer in Kubernetes SA JWTs |
| `ASB_K8S_PUBLIC_KEY_FILE` | Public key for JWT verification |

### Optional

| Variable | Purpose |
|----------|---------|
| `ASB_K8S_AUDIENCE` | Expected audience claim |
| `ASB_ADDR` | Listen address (default `:8080`) |
| `ASB_DEV_TENANT_ID` | Tenant ID for local development |
| `ASB_POSTGRES_DSN` | Enables Postgres repository |
| `ASB_REDIS_ADDR` | Enables Redis runtime store |
| `ASB_REDIS_PASSWORD` | Redis authentication |
| `ASB_HTTP_MAX_BODY_BYTES` | Maximum JSON request body size |
| `ASB_HTTP_READ_TIMEOUT` | HTTP server read timeout |
| `ASB_HTTP_WRITE_TIMEOUT` | HTTP server write timeout |
| `ASB_HTTP_IDLE_TIMEOUT` | HTTP server idle timeout |
| `ASB_HTTP_DEFAULT_TIMEOUT` | Default JSON handler timeout |
| `ASB_HTTP_GRANT_TIMEOUT` | Grant and approval handler timeout |
| `ASB_HTTP_PROXY_TIMEOUT` | Proxy handler timeout |
| `ASB_HTTP_RATE_LIMIT_RPS` | Sustained per-IP JSON API rate limit |
| `ASB_HTTP_RATE_LIMIT_BURST` | Burst size for the per-IP JSON API limiter |
| `ASB_HTTP_RATE_LIMIT_MAX_AGE` | Idle lifetime for per-IP limiter entries |
| `ASB_HTTP_RATE_LIMIT_CLEANUP_INTERVAL` | Cleanup cadence for stale per-IP limiter entries |
| `ASB_HTTP_READY_TIMEOUT` | Dependency timeout for `/readyz` |
| `ASB_HTTP_SHUTDOWN_TIMEOUT` | API shutdown drain timeout |
| `ASB_GITHUB_TOKEN` | Static GitHub token (dev) |
| `ASB_GITHUB_API_BASE_URL` | GitHub API base URL override |
| `ASB_GITHUB_APP_ID` | GitHub App ID |
| `ASB_GITHUB_APP_PRIVATE_KEY_FILE` | GitHub App private key |
| `ASB_GITHUB_APP_PERMISSIONS_JSON` | GitHub App token permissions |
| `ASB_DELEGATION_ISSUER` | Delegation JWT issuer |
| `ASB_DELEGATION_PUBLIC_KEY_FILE` | Delegation JWT public key |
| `ASB_SESSION_SIGNING_PRIVATE_KEY_FILE` | Ed25519 private key for session tokens |
| `ASB_VAULT_ADDR` | Vault server address |
| `ASB_VAULT_TOKEN` | Vault authentication token |
| `ASB_VAULT_NAMESPACE` | Vault namespace |
| `ASB_VAULT_ROLE` | Vault DB role name |
| `ASB_VAULT_DSN_TEMPLATE` | DSN template for rendered credentials |
| `ASB_BROWSER_ORIGIN` | Allowed browser origin (demo) |
| `ASB_BROWSER_USERNAME` | Browser credential username (demo) |
| `ASB_BROWSER_PASSWORD` | Browser credential password (demo) |
| `ASB_BROWSER_SELECTOR_USERNAME` | CSS selector for username field (demo) |
| `ASB_BROWSER_SELECTOR_PASSWORD` | CSS selector for password field (demo) |
| `ASB_NOTIFICATIONS_BASE_URL` | Shared notifications service base URL for pending approval delivery |
| `ASB_NOTIFICATIONS_RECIPIENT_ID` | Recipient or queue ID for approval notifications |
| `ASB_NOTIFICATIONS_CHANNEL` | Delivery channel for approval notifications (`slack`, `email`, `webhook`, `in_app`) |
| `ASB_NOTIFICATIONS_WORKSPACE_ID` | Workspace override for approval notifications (defaults to approval tenant ID) |
| `ASB_NOTIFICATIONS_BEARER_TOKEN` | Optional bearer token forwarded to the notifications service |
| `ASB_PUBLIC_BASE_URL` | Optional public ASB base URL used to embed approve/deny endpoints in notification metadata |

## Local development

```bash
make proto         # lint and regenerate protobuf/ConnectRPC stubs with buf
make proto-check   # verify generated protobuf/ConnectRPC stubs are current
make fmt           # format Go source
make vet           # go vet
make test          # run all tests
make migrate       # apply Postgres schema (requires ASB_POSTGRES_DSN)
make run-api       # start the API server
make run-worker    # start the cleanup worker
```

### Example startup

```bash
export ASB_K8S_ISSUER="https://cluster.example"
export ASB_K8S_PUBLIC_KEY_FILE="./dev/keys/k8s-sa.pub"
export ASB_GITHUB_TOKEN="ghp_..."
make run-api
```

### Health checks

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
curl http://localhost:8080/metrics
```

### HTTP rate limiting

The JSON API now applies per-IP rate limiting through the shared `service-runtime/ratelimit` middleware. Health and metrics endpoints remain exempt. Defaults are tuned for internal service traffic and can be overridden with the `ASB_HTTP_RATE_LIMIT_*` env vars above.

### Metrics

ASB now exposes Prometheus metrics on `/metrics` through the shared `service-runtime/observability` package. The current slice covers HTTP request counters and request-latency histograms across the broker entrypoints, plus Postgres pool gauges when `ASB_POSTGRES_DSN` is configured.

### Shared approval notifications

If `ASB_NOTIFICATIONS_BASE_URL`, `ASB_NOTIFICATIONS_RECIPIENT_ID`, and `ASB_NOTIFICATIONS_CHANNEL` are set, pending approvals are sent through the shared `notifications` service with structured metadata for `approval_id`, `grant_id`, `tenant_id`, `tool`, `capability`, `resource_ref`, and expiration details. When `ASB_PUBLIC_BASE_URL` is set, ASB also includes approve/deny endpoint hints in that metadata for downstream tooling.

## Testing

Test-first development across the critical broker behavior:

- attestation and signed delegation validation
- policy evaluation with conditions, trust tags, and TTL clamping
- grant approval, issuance, and revocation flows
- GitHub App token generation, caching, and proxy execution with budget enforcement
- browser relay registration and single-use unwrap
- Vault credential brokering and lease revocation
- Postgres repository persistence
- Redis runtime budget and relay state
- JSON/HTTP and ConnectRPC transport adapters
- cleanup worker expiry handling

```bash
make test
```

## Security properties

- session tokens are short-lived and Ed25519-signed
- grants are bound to a single tool, capability, resource, and delivery mode
- proxy execution is operation-allowlisted with per-handle budget enforcement
- browser unwrap is single-use and recipient-bound (session, key, origin, tab)
- browser fill responses are explicit selector/value pairs, never credential blobs
- GitHub proxy never exposes the underlying token to the agent
- wrapped artifacts track downstream lease IDs for revocation on expiry
- audit events are emitted from the service layer for all grant and session lifecycle transitions
