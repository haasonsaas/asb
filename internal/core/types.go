package core

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type SessionState string

const (
	SessionStateActive  SessionState = "active"
	SessionStateRevoked SessionState = "revoked"
	SessionStateExpired SessionState = "expired"
)

type GrantState string

const (
	GrantStatePending   GrantState = "pending"
	GrantStateApproved  GrantState = "approved"
	GrantStateDenied    GrantState = "denied"
	GrantStateIssued    GrantState = "issued"
	GrantStateDelivered GrantState = "delivered"
	GrantStateUsed      GrantState = "used"
	GrantStateRevoked   GrantState = "revoked"
	GrantStateExpired   GrantState = "expired"
)

type ApprovalState string

const (
	ApprovalStatePending  ApprovalState = "pending"
	ApprovalStateApproved ApprovalState = "approved"
	ApprovalStateDenied   ApprovalState = "denied"
	ApprovalStateExpired  ApprovalState = "expired"
)

type ApprovalMode string

const (
	ApprovalModeNone      ApprovalMode = "none"
	ApprovalModeLiveHuman ApprovalMode = "live_human"
)

type DeliveryMode string

const (
	DeliveryModeProxy         DeliveryMode = "proxy"
	DeliveryModeMintedToken   DeliveryMode = "minted_token"
	DeliveryModeWrappedSecret DeliveryMode = "wrapped_secret"
)

type DeliveryKind string

const (
	DeliveryKindProxyHandle   DeliveryKind = "proxy_handle"
	DeliveryKindMintedToken   DeliveryKind = "minted_token"
	DeliveryKindWrappedSecret DeliveryKind = "wrapped_secret"
)

type ArtifactKind string

const (
	ArtifactKindProxyHandle   ArtifactKind = "proxy_handle"
	ArtifactKindMintedToken   ArtifactKind = "minted_token"
	ArtifactKindWrappedSecret ArtifactKind = "wrapped_secret"
)

type ArtifactState string

const (
	ArtifactStateIssued  ArtifactState = "issued"
	ArtifactStateUsed    ArtifactState = "used"
	ArtifactStateRevoked ArtifactState = "revoked"
	ArtifactStateExpired ArtifactState = "expired"
)

type RuntimeClass string

const (
	RuntimeClassHosted  RuntimeClass = "hosted"
	RuntimeClassSidecar RuntimeClass = "sidecar"
	RuntimeClassBrowser RuntimeClass = "browser"
)

type WorkloadIdentityType string

const (
	WorkloadIdentityTypeK8SSA WorkloadIdentityType = "k8s_sa"
	WorkloadIdentityTypeOIDC  WorkloadIdentityType = "oidc"
)

type AttestationKind string

const (
	AttestationKindK8SServiceAccountJWT AttestationKind = "k8s_sa_jwt"
	AttestationKindOIDCJWT              AttestationKind = "oidc_jwt"
)

type ResourceKind string

const (
	ResourceKindGitHubRepo    ResourceKind = "github_repo"
	ResourceKindDBRole        ResourceKind = "db_role"
	ResourceKindBrowserOrigin ResourceKind = "browser_origin"
)

type WorkloadIdentity struct {
	Type           WorkloadIdentityType
	Issuer         string
	Subject        string
	Audience       string
	Namespace      string
	ServiceAccount string
	Attributes     map[string]string
}

type Delegation struct {
	ID                  string
	Issuer              string
	Subject             string
	TenantID            string
	AgentID             string
	AllowedCapabilities []string
	ResourceFilters     map[string][]string
	ExpiresAt           time.Time
}

type Session struct {
	ID               string
	TenantID         string
	AgentID          string
	RunID            string
	TokenID          string
	WorkloadIdentity WorkloadIdentity
	Delegation       *Delegation
	ToolContext      []string
	WorkloadHash     string
	ExpiresAt        time.Time
	State            SessionState
	CreatedAt        time.Time
}

type Tool struct {
	TenantID             string
	Tool                 string
	ManifestHash         string
	RuntimeClass         RuntimeClass
	AllowedDeliveryModes []DeliveryMode
	AllowedCapabilities  []string
	EgressAllowlist      []string
	LoggingMode          string
	TrustTags            []string
}

type Policy struct {
	TenantID             string
	Capability           string
	ResourceKind         ResourceKind
	AllowedDeliveryModes []DeliveryMode
	DefaultTTL           time.Duration
	MaxTTL               time.Duration
	ApprovalMode         ApprovalMode
	RequiredToolTags     []string
	Condition            string
}

type Grant struct {
	ID            string
	TenantID      string
	SessionID     string
	Capability    string
	ResourceRef   string
	Tool          string
	DeliveryMode  DeliveryMode
	RequestedTTL  time.Duration
	EffectiveTTL  time.Duration
	ApprovalID    *string
	ConnectorKind string
	ArtifactRef   *string
	State         GrantState
	Reason        string
	Delivery      *Delivery
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type Approval struct {
	ID          string
	TenantID    string
	GrantID     string
	RequestedBy string
	ApprovedBy  *string
	Reason      string
	Comment     string
	ExpiresAt   time.Time
	State       ApprovalState
	CreatedAt   time.Time
}

type Artifact struct {
	ID               string
	TenantID         string
	SessionID        string
	GrantID          string
	Handle           string
	Kind             ArtifactKind
	ConnectorKind    string
	SecretData       map[string]string
	Metadata         map[string]string
	RecipientBinding map[string]string
	SingleUse        bool
	State            ArtifactState
	ExpiresAt        time.Time
	CreatedAt        time.Time
	UsedAt           *time.Time
}

type BrowserRelaySession struct {
	SessionID string
	TenantID  string
	KeyID     string
	PublicKey string
	Origin    string
	TabID     string
	Selectors map[string]string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type BrowserFillField struct {
	Name     string
	Selector string
	Value    string
}

type AuditEvent struct {
	EventID     string
	TenantID    string
	EventType   string
	SessionID   string
	RunID       string
	GrantID     string
	Actor       string
	Tool        string
	Capability  string
	ResourceRef string
	Metadata    map[string]any
	CreatedAt   time.Time
}

type ApprovalCallbackConfig struct {
	URL string
}

type Attestation struct {
	Kind  AttestationKind
	Token string
}

type CreateSessionRequest struct {
	TenantID            string
	AgentID             string
	RunID               string
	ToolContext         []string
	Attestation         *Attestation
	DelegationAssertion string
}

type CreateSessionResponse struct {
	SessionID    string
	SessionToken string
	ExpiresAt    time.Time
}

type RequestGrantRequest struct {
	SessionToken string
	Tool         string
	Capability   string
	ResourceRef  string
	DeliveryMode DeliveryMode
	TTL          time.Duration
	Reason       string
}

type RequestGrantResponse struct {
	GrantID    string
	State      GrantState
	ApprovalID string
	Delivery   *Delivery
	ExpiresAt  time.Time
}

type ApproveGrantRequest struct {
	ApprovalID string
	Approver   string
	Comment    string
}

type DenyGrantRequest struct {
	ApprovalID string
	Approver   string
	Comment    string
}

type RevokeGrantRequest struct {
	GrantID string
	Reason  string
}

type RevokeSessionRequest struct {
	SessionID string
	Reason    string
}

type ExecuteGitHubProxyRequest struct {
	ProxyHandle string
	Operation   string
	Params      map[string]any
}

type ExecuteGitHubProxyResponse struct {
	Payload     []byte
	ContentType string
}

type RegisterBrowserRelayRequest struct {
	SessionToken string
	KeyID        string
	PublicKey    string
	Origin       string
	TabID        string
	Selectors    map[string]string
}

type RegisterBrowserRelayResponse struct {
	SessionID string
	KeyID     string
	ExpiresAt time.Time
}

type UnwrapArtifactRequest struct {
	SessionToken string
	ArtifactID   string
	KeyID        string
	Origin       string
	TabID        string
}

type UnwrapArtifactResponse struct {
	ArtifactID string
	Origin     string
	AutoSubmit bool
	Fields     []BrowserFillField
}

type Delivery struct {
	Kind       DeliveryKind
	Handle     string
	Token      string
	ArtifactID string
}

type ResourceDescriptor struct {
	Kind   ResourceKind
	Name   string
	Origin string
}

type DecisionInput struct {
	Session  *Session
	Request  *RequestGrantRequest
	Tool     *Tool
	Resource ResourceDescriptor
}

type Decision struct {
	Allowed      bool
	Reason       string
	EffectiveTTL time.Duration
	ApprovalMode ApprovalMode
	Policy       Policy
}

type ProxyBudget struct {
	MaxConcurrent int
	MaxRequests   int
	MaxBytes      int64
	Timeout       time.Duration
}

type SessionClaims struct {
	SessionID    string
	TenantID     string
	AgentID      string
	RunID        string
	TokenID      string
	ToolContext  []string
	WorkloadHash string
	ExpiresAt    time.Time
}

type ValidateResourceRequest struct {
	TenantID    string
	Capability  string
	ResourceRef string
}

type IssueRequest struct {
	Session  *Session
	Grant    *Grant
	Resource ResourceDescriptor
}

type IssuedArtifact struct {
	Kind       ArtifactKind
	Metadata   map[string]string
	SecretData map[string]string
	ExpiresAt  time.Time
}

type RevokeRequest struct {
	Session  *Session
	Grant    *Grant
	Artifact *Artifact
	Reason   string
}

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	New(prefix string) string
}

type AttestationVerifier interface {
	Verify(ctx context.Context, in *Attestation) (*WorkloadIdentity, error)
}

type DelegationValidator interface {
	Validate(ctx context.Context, raw string, tenantID string, agentID string) (*Delegation, error)
}

type PolicyEngine interface {
	Evaluate(ctx context.Context, in *DecisionInput) (*Decision, error)
}

type ToolRegistry interface {
	Put(ctx context.Context, tool Tool) error
	Get(ctx context.Context, tenantID string, tool string) (*Tool, error)
}

type Connector interface {
	Kind() string
	ValidateResource(ctx context.Context, req ValidateResourceRequest) error
	Issue(ctx context.Context, req IssueRequest) (*IssuedArtifact, error)
	Revoke(ctx context.Context, req RevokeRequest) error
}

type ConnectorResolver interface {
	Resolve(ctx context.Context, capability string, resourceRef string) (Connector, error)
}

type DeliveryAdapter interface {
	Mode() DeliveryMode
	Deliver(ctx context.Context, art *IssuedArtifact, sess *Session, grant *Grant) (*Delivery, error)
}

type ApprovalNotifier interface {
	NotifyPending(ctx context.Context, app *ApprovalCallbackConfig, approval *Approval, grant *Grant) error
}

type AuditSink interface {
	Append(ctx context.Context, evt *AuditEvent) error
}

type Repository interface {
	SaveSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	ListGrantsBySession(ctx context.Context, sessionID string) ([]*Grant, error)
	ListExpiredSessions(ctx context.Context, before time.Time, limit int) ([]*Session, error)
	SaveGrant(ctx context.Context, grant *Grant) error
	GetGrant(ctx context.Context, grantID string) (*Grant, error)
	ListExpiredGrants(ctx context.Context, before time.Time, limit int) ([]*Grant, error)
	SaveApproval(ctx context.Context, approval *Approval) error
	GetApproval(ctx context.Context, approvalID string) (*Approval, error)
	ListExpiredApprovals(ctx context.Context, before time.Time, limit int) ([]*Approval, error)
	SaveArtifact(ctx context.Context, artifact *Artifact) error
	GetArtifact(ctx context.Context, artifactID string) (*Artifact, error)
	GetArtifactByHandle(ctx context.Context, handle string) (*Artifact, error)
	UseArtifact(ctx context.Context, artifactID string, usedAt time.Time) (*Artifact, error)
	ListExpiredArtifacts(ctx context.Context, before time.Time, limit int) ([]*Artifact, error)
}

type SessionTokenManager interface {
	Sign(session *Session) (string, error)
	Verify(raw string) (*SessionClaims, error)
}

type RuntimeStore interface {
	RegisterProxyHandle(ctx context.Context, handle string, budget ProxyBudget, expiresAt time.Time) error
	AcquireProxyRequest(ctx context.Context, handle string) error
	CompleteProxyRequest(ctx context.Context, handle string, responseBytes int64) error
	SaveRelaySession(ctx context.Context, relay *BrowserRelaySession) error
	GetRelaySession(ctx context.Context, sessionID string) (*BrowserRelaySession, error)
	RevokeSessionToken(ctx context.Context, tokenID string, expiresAt time.Time) error
	IsSessionTokenRevoked(ctx context.Context, tokenID string) (bool, error)
}

type GitHubProxyExecutor interface {
	Execute(ctx context.Context, artifact *Artifact, operation string, params map[string]any) ([]byte, error)
}

func ParseResource(resourceRef string) (ResourceDescriptor, error) {
	switch {
	case strings.HasPrefix(resourceRef, "github:repo:"):
		return ResourceDescriptor{
			Kind: ResourceKindGitHubRepo,
			Name: strings.TrimPrefix(resourceRef, "github:repo:"),
		}, nil
	case strings.HasPrefix(resourceRef, "dbrole:"):
		return ResourceDescriptor{
			Kind: ResourceKindDBRole,
			Name: strings.TrimPrefix(resourceRef, "dbrole:"),
		}, nil
	case strings.HasPrefix(resourceRef, "browser_origin:"):
		origin := strings.TrimPrefix(resourceRef, "browser_origin:")
		return ResourceDescriptor{
			Kind:   ResourceKindBrowserOrigin,
			Name:   origin,
			Origin: origin,
		}, nil
	default:
		return ResourceDescriptor{}, fmt.Errorf("%w: unsupported resource ref %q", ErrInvalidRequest, resourceRef)
	}
}
