package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/asb/internal/app"
	approvalnotifications "github.com/evalops/asb/internal/approval/notifications"
	auditmemory "github.com/evalops/asb/internal/audit/memory"
	"github.com/evalops/asb/internal/authn/delegationjwt"
	"github.com/evalops/asb/internal/authn/k8s"
	"github.com/evalops/asb/internal/authz/policy"
	"github.com/evalops/asb/internal/authz/toolregistry"
	browserconnector "github.com/evalops/asb/internal/connectors/browser"
	githubconnector "github.com/evalops/asb/internal/connectors/github"
	"github.com/evalops/asb/internal/connectors/resolver"
	"github.com/evalops/asb/internal/connectors/vaultdb"
	"github.com/evalops/asb/internal/core"
	"github.com/evalops/asb/internal/crypto/sessionjwt"
	proxydelivery "github.com/evalops/asb/internal/delivery/proxy"
	wrappeddelivery "github.com/evalops/asb/internal/delivery/wrapped"
	memstore "github.com/evalops/asb/internal/store/memory"
	postgresstore "github.com/evalops/asb/internal/store/postgres"
	redisstore "github.com/evalops/asb/internal/store/redis"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
)

type ServiceOption func(*serviceOptions)

type serviceOptions struct {
	requireVerifier bool
}

type readinessProbe func(context.Context) error

type ServiceRuntime struct {
	Service *app.Service
	Cleanup func()
	Health  *HealthChecker
	DBStats func() sql.DBStats
}

type HealthChecker struct {
	postgresProbe      readinessProbe
	redisProbe         readinessProbe
	sessionTokensReady bool
}

type ReadinessCheck struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type ReadinessReport struct {
	Ready  bool                      `json:"ready"`
	Checks map[string]ReadinessCheck `json:"checks"`
}

func WithVerificationOptional() ServiceOption {
	return func(options *serviceOptions) {
		options.requireVerifier = false
	}
}

func NewService(ctx context.Context, logger *slog.Logger, options ...ServiceOption) (*app.Service, func(), error) {
	runtime, err := NewServiceRuntime(ctx, logger, options...)
	if err != nil {
		return nil, nil, err
	}
	return runtime.Service, runtime.Cleanup, nil
}

func NewServiceRuntime(ctx context.Context, logger *slog.Logger, options ...ServiceOption) (*ServiceRuntime, error) {
	config := serviceOptions{requireVerifier: true}
	for _, option := range options {
		option(&config)
	}

	verifier, err := newVerifier(config.requireVerifier)
	if err != nil {
		return nil, err
	}
	sessionTokens, err := newSessionTokenManager()
	if err != nil {
		return nil, err
	}
	repository, cleanupRepository, postgresProbe, dbStats, err := newRepository(ctx)
	if err != nil {
		return nil, err
	}
	runtimeStore, cleanupRuntime, redisProbe, err := newRuntimeStore(ctx)
	if err != nil {
		cleanupRepository()
		return nil, err
	}

	auditSink := auditmemory.NewSink()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	connectorOptions := []resolver.Option{
		resolver.WithGitHub(githubconnector.NewConnector(githubconnector.Config{})),
	}

	githubProxy, err := newGitHubProxyExecutor()
	if err != nil {
		cleanupRuntime()
		cleanupRepository()
		return nil, err
	}
	approvalNotifier, err := newApprovalNotifier()
	if err != nil {
		cleanupRuntime()
		cleanupRepository()
		return nil, err
	}

	tenantID := getenv("ASB_DEV_TENANT_ID", "t_dev")
	mustRegisterToolAndPolicy(ctx, logger, tools, engine, tenantID, core.Tool{
		TenantID:             tenantID,
		Tool:                 "github",
		ManifestHash:         "sha256:dev",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		AllowedCapabilities:  []string{"repo.read"},
		TrustTags:            []string{"trusted", "github"},
	}, core.Policy{
		TenantID:             tenantID,
		Capability:           "repo.read",
		ResourceKind:         core.ResourceKindGitHubRepo,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               10 * time.Minute,
		ApprovalMode:         core.ApprovalModeNone,
		RequiredToolTags:     []string{"trusted", "github"},
		Condition:            `request.tool == "github"`,
	})

	if origin := os.Getenv("ASB_BROWSER_ORIGIN"); origin != "" {
		username := os.Getenv("ASB_BROWSER_USERNAME")
		password := os.Getenv("ASB_BROWSER_PASSWORD")
		userSelector := getenv("ASB_BROWSER_SELECTOR_USERNAME", "#username")
		passSelector := getenv("ASB_BROWSER_SELECTOR_PASSWORD", "#password")
		connectorOptions = append(connectorOptions, resolver.WithBrowser(browserconnector.NewConnector(browserconnector.Config{
			Credentials: browserconnector.StaticCredentialStore(map[string]browserconnector.Credential{
				origin: {
					Username: username,
					Password: password,
				},
			}),
			SelectorMaps: map[string]browserconnector.SelectorMap{
				origin: {
					Username: userSelector,
					Password: passSelector,
				},
			},
		})))
		mustRegisterToolAndPolicy(ctx, logger, tools, engine, tenantID, core.Tool{
			TenantID:             tenantID,
			Tool:                 "browser",
			ManifestHash:         "sha256:dev-browser",
			RuntimeClass:         core.RuntimeClassBrowser,
			AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
			AllowedCapabilities:  []string{"browser.login"},
			TrustTags:            []string{"trusted", "browser"},
		}, core.Policy{
			TenantID:             tenantID,
			Capability:           "browser.login",
			ResourceKind:         core.ResourceKindBrowserOrigin,
			AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
			DefaultTTL:           2 * time.Minute,
			MaxTTL:               5 * time.Minute,
			ApprovalMode:         core.ApprovalModeLiveHuman,
			RequiredToolTags:     []string{"trusted", "browser"},
			Condition:            `request.origin == "` + origin + `" && session.tool_context.exists(t, t == "browser")`,
		})
	}

	if vaultAddr := os.Getenv("ASB_VAULT_ADDR"); vaultAddr != "" {
		role := getenv("ASB_VAULT_ROLE", "analytics_ro")
		dsnTemplate := os.Getenv("ASB_VAULT_DSN_TEMPLATE")
		if dsnTemplate != "" {
			vaultClient := vaultdb.NewHTTPClient(vaultdb.HTTPClientConfig{
				BaseURL:   vaultAddr,
				Token:     os.Getenv("ASB_VAULT_TOKEN"),
				Namespace: os.Getenv("ASB_VAULT_NAMESPACE"),
			})
			connectorOptions = append(connectorOptions, resolver.WithVaultDB(vaultdb.NewConnector(vaultdb.Config{
				Client: vaultClient,
				RoleDSNs: map[string]string{
					role: dsnTemplate,
				},
			})))
			mustRegisterToolAndPolicy(ctx, logger, tools, engine, tenantID, core.Tool{
				TenantID:             tenantID,
				Tool:                 "db",
				ManifestHash:         "sha256:dev-db",
				RuntimeClass:         core.RuntimeClassSidecar,
				AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
				AllowedCapabilities:  []string{"db.read"},
				TrustTags:            []string{"trusted", "db"},
			}, core.Policy{
				TenantID:             tenantID,
				Capability:           "db.read",
				ResourceKind:         core.ResourceKindDBRole,
				AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
				DefaultTTL:           10 * time.Minute,
				MaxTTL:               30 * time.Minute,
				ApprovalMode:         core.ApprovalModeNone,
				RequiredToolTags:     []string{"trusted", "db"},
				Condition:            `true`,
			})
		}
	}

	delegationValidator, err := newDelegationValidator()
	if err != nil {
		cleanupRuntime()
		cleanupRepository()
		return nil, err
	}

	svc, err := app.NewService(app.Config{
		Logger:              logger,
		Repository:          repository,
		Verifier:            verifier,
		DelegationValidator: delegationValidator,
		SessionTokens:       sessionTokens,
		Policy:              engine,
		Tools:               tools,
		Connectors:          resolver.NewStaticResolver(connectorOptions...),
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeProxy:         proxydelivery.NewAdapter(),
			core.DeliveryModeWrappedSecret: wrappeddelivery.NewAdapter(),
		},
		Audit:            auditSink,
		Runtime:          runtimeStore,
		ApprovalNotifier: approvalNotifier,
		GitHubProxy:      githubProxy,
	})
	if err != nil {
		cleanupRuntime()
		cleanupRepository()
		return nil, err
	}

	return &ServiceRuntime{
		Service: svc,
		Cleanup: func() {
			cleanupRuntime()
			cleanupRepository()
		},
		Health: &HealthChecker{
			postgresProbe:      postgresProbe,
			redisProbe:         redisProbe,
			sessionTokensReady: sessionTokens != nil,
		},
		DBStats: dbStats,
	}, nil
}

func (h *HealthChecker) CheckReadiness(ctx context.Context) ReadinessReport {
	report := ReadinessReport{
		Ready: true,
		Checks: map[string]ReadinessCheck{
			"session_signing_key": readyCheck(h.sessionTokensReady),
			"postgres":            disabledCheck(),
			"redis":               disabledCheck(),
		},
	}

	if h.postgresProbe != nil {
		report.Checks["postgres"] = runProbe(ctx, h.postgresProbe)
		if report.Checks["postgres"].Status != "ok" {
			report.Ready = false
		}
	}
	if h.redisProbe != nil {
		report.Checks["redis"] = runProbe(ctx, h.redisProbe)
		if report.Checks["redis"].Status != "ok" {
			report.Ready = false
		}
	}
	if report.Checks["session_signing_key"].Status != "ok" {
		report.Ready = false
	}

	return report
}

func readyCheck(ok bool) ReadinessCheck {
	if ok {
		return ReadinessCheck{Status: "ok"}
	}
	return ReadinessCheck{Status: "error", Message: "session token manager is not configured"}
}

func disabledCheck() ReadinessCheck {
	return ReadinessCheck{Status: "disabled"}
}

func runProbe(ctx context.Context, probe readinessProbe) ReadinessCheck {
	if err := probe(ctx); err != nil {
		return ReadinessCheck{Status: "error", Message: err.Error()}
	}
	return ReadinessCheck{Status: "ok"}
}

func newVerifier(require bool) (core.AttestationVerifier, error) {
	issuer := os.Getenv("ASB_K8S_ISSUER")
	publicKeyFile := os.Getenv("ASB_K8S_PUBLIC_KEY_FILE")
	if issuer == "" || publicKeyFile == "" {
		if require {
			return nil, fmt.Errorf("missing verifier configuration: ASB_K8S_ISSUER and ASB_K8S_PUBLIC_KEY_FILE are required")
		}
		return noopVerifier{}, nil
	}
	publicKey, err := loadPublicKey(publicKeyFile)
	if err != nil {
		return nil, err
	}
	return k8s.NewVerifier(k8s.Config{
		Issuer:   issuer,
		Audience: getenv("ASB_K8S_AUDIENCE", "asb-control-plane"),
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
}

type noopVerifier struct{}

func (noopVerifier) Verify(context.Context, *core.Attestation) (*core.WorkloadIdentity, error) {
	return nil, fmt.Errorf("attestation verification is not configured in this process")
}

func newSessionTokenManager() (core.SessionTokenManager, error) {
	if path := os.Getenv("ASB_SESSION_SIGNING_PRIVATE_KEY_FILE"); path != "" {
		privateKey, err := loadEd25519PrivateKey(path)
		if err != nil {
			return nil, err
		}
		return sessionjwt.NewManager(privateKey)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return sessionjwt.NewManager(privateKey)
}

func newDelegationValidator() (core.DelegationValidator, error) {
	issuer := os.Getenv("ASB_DELEGATION_ISSUER")
	path := os.Getenv("ASB_DELEGATION_PUBLIC_KEY_FILE")
	if issuer == "" || path == "" {
		return nil, nil
	}
	publicKey, err := loadEd25519PublicKey(path)
	if err != nil {
		return nil, err
	}
	return delegationjwt.NewValidator(delegationjwt.Config{
		Issuers: map[string]ed25519.PublicKey{
			issuer: publicKey,
		},
	})
}

func newGitHubProxyExecutor() (core.GitHubProxyExecutor, error) {
	var tokenSource githubconnector.RepoTokenSource

	if appIDRaw := os.Getenv("ASB_GITHUB_APP_ID"); appIDRaw != "" && os.Getenv("ASB_GITHUB_APP_PRIVATE_KEY_FILE") != "" {
		appID, err := strconv.ParseInt(appIDRaw, 10, 64)
		if err != nil {
			return nil, err
		}
		privateKey, err := loadRSAPrivateKey(os.Getenv("ASB_GITHUB_APP_PRIVATE_KEY_FILE"))
		if err != nil {
			return nil, err
		}
		permissions := map[string]string{}
		if raw := os.Getenv("ASB_GITHUB_APP_PERMISSIONS_JSON"); raw != "" {
			if err := json.Unmarshal([]byte(raw), &permissions); err != nil {
				return nil, err
			}
		}
		tokenSource, err = githubconnector.NewAppTokenSource(githubconnector.AppTokenSourceConfig{
			AppID:       appID,
			PrivateKey:  privateKey,
			BaseURL:     getenv("ASB_GITHUB_API_BASE_URL", "https://api.github.com"),
			Permissions: permissions,
		})
		if err != nil {
			return nil, err
		}
	} else if token := os.Getenv("ASB_GITHUB_TOKEN"); token != "" {
		tokenSource = githubconnector.StaticTokenSource(token)
	}

	if tokenSource == nil {
		return nil, nil
	}
	return githubconnector.NewHTTPExecutor(githubconnector.ExecutorConfig{
		BaseURL:     getenv("ASB_GITHUB_API_BASE_URL", "https://api.github.com"),
		TokenSource: tokenSource,
	}), nil
}

func newApprovalNotifier() (core.ApprovalNotifier, error) {
	baseURL := strings.TrimSpace(os.Getenv("ASB_NOTIFICATIONS_BASE_URL"))
	recipientID := strings.TrimSpace(os.Getenv("ASB_NOTIFICATIONS_RECIPIENT_ID"))
	channelRaw := strings.TrimSpace(os.Getenv("ASB_NOTIFICATIONS_CHANNEL"))
	workspaceID := strings.TrimSpace(os.Getenv("ASB_NOTIFICATIONS_WORKSPACE_ID"))
	bearerToken := strings.TrimSpace(os.Getenv("ASB_NOTIFICATIONS_BEARER_TOKEN"))
	publicBaseURL := strings.TrimSpace(os.Getenv("ASB_PUBLIC_BASE_URL"))

	if baseURL == "" {
		if recipientID != "" || channelRaw != "" || workspaceID != "" || bearerToken != "" || publicBaseURL != "" {
			return nil, fmt.Errorf("ASB_NOTIFICATIONS_BASE_URL is required when approval notifications are configured")
		}
		return nil, nil
	}

	channel, err := approvalnotifications.ParseChannel(channelRaw)
	if err != nil {
		return nil, fmt.Errorf("parse ASB_NOTIFICATIONS_CHANNEL: %w", err)
	}

	return approvalnotifications.NewNotifier(approvalnotifications.Config{
		BaseURL:       baseURL,
		BearerToken:   bearerToken,
		WorkspaceID:   workspaceID,
		RecipientID:   recipientID,
		Channel:       channel,
		PublicBaseURL: publicBaseURL,
	})
}

func newRepository(ctx context.Context) (core.Repository, func(), readinessProbe, func() sql.DBStats, error) {
	if dsn := os.Getenv("ASB_POSTGRES_DSN"); dsn != "" {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return postgresstore.NewRepository(pool), pool.Close, pool.Ping, pgxPoolDBStats(pool), nil
	}
	return memstore.NewRepository(), func() {}, nil, nil, nil
}

func newRuntimeStore(ctx context.Context) (core.RuntimeStore, func(), readinessProbe, error) {
	if addr := os.Getenv("ASB_REDIS_ADDR"); addr != "" {
		client := goredis.NewClient(&goredis.Options{
			Addr:     addr,
			Password: os.Getenv("ASB_REDIS_PASSWORD"),
			DB:       0,
		})
		if err := client.Ping(ctx).Err(); err != nil {
			return nil, nil, nil, err
		}
		return redisstore.NewRuntimeStore(client), func() { _ = client.Close() }, func(ctx context.Context) error {
			return client.Ping(ctx).Err()
		}, nil
	}
	return memstore.NewRuntimeStore(), func() {}, nil, nil
}

func pgxPoolDBStats(pool *pgxpool.Pool) func() sql.DBStats {
	if pool == nil {
		return nil
	}
	return func() sql.DBStats {
		stats := pool.Stat()
		return sql.DBStats{
			MaxOpenConnections: int(stats.MaxConns()),
			OpenConnections:    int(stats.TotalConns()),
			InUse:              int(stats.AcquiredConns()),
			Idle:               int(stats.IdleConns()),
		}
	}
}

func loadPublicKey(path string) (any, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("decode pem: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	cert, certErr := x509.ParseCertificate(block.Bytes)
	if certErr == nil {
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("parse public key: %w", err)
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	key, err := loadPublicKey(path)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ed25519.PublicKey", key)
	}
	return publicKey, nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("decode pem: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want ed25519.PrivateKey", key)
	}
	return privateKey, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("decode pem: no PEM block found")
	}
	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want *rsa.PrivateKey", key)
	}
	return privateKey, nil
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func mustRegisterToolAndPolicy(ctx context.Context, logger *slog.Logger, tools *toolregistry.Registry, engine *policy.Engine, tenantID string, tool core.Tool, pol core.Policy) {
	if err := tools.Put(ctx, tool); err != nil {
		logger.Error("register tool", "tenant_id", tenantID, "tool", tool.Tool, "error", err)
		os.Exit(1)
	}
	if err := engine.Put(pol); err != nil {
		logger.Error("register policy", "tenant_id", tenantID, "capability", pol.Capability, "error", err)
		os.Exit(1)
	}
}
