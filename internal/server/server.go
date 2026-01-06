package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/grepplabs/casbin-forward-auth/internal/auth"
	"github.com/grepplabs/casbin-forward-auth/internal/jwt"
	"github.com/grepplabs/casbin-forward-auth/internal/metrics"
	tlsserverconfig "github.com/grepplabs/cert-source/tls/server/config"
	"github.com/grepplabs/loggo/zlog"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	slogzap "github.com/samber/slog-zap/v2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/grepplabs/casbin-forward-auth/internal/config"
)

const (
	AuthV1Path            = "/v1/auth"
	HeaderForwardedMethod = "X-Forwarded-Method"
	HeaderForwardedProto  = "X-Forwarded-Proto"
	HeaderForwardedHost   = "X-Forwarded-Host"
	HeaderForwardedURI    = "X-Forwarded-Uri"
	HeaderForwardedFor    = "X-Forwarded-For"
	HeaderHost            = "Host"
	HeaderWWWAuthenticate = "WWW-Authenticate"
	HeaderOriginalMethod  = "X-Original-Method"
	HeaderOriginalURI     = "X-Original-Uri"
	HeaderOriginalURL     = "X-Original-Url"
)

var (
	ErrUnauthorized              = errors.New("unauthorized")
	ErrMissingForwardAuthHeaders = errors.New("missing forward auth headers; verify the configured auth-header-source")
	ErrInvalidRequestHeaders     = errors.New("missing required request headers")
)

func buildEngine(registry *prometheus.Registry, cfg config.Config) (*gin.Engine, Closers, error) {
	closers := make(Closers, 0)

	gin.SetMode(gin.ReleaseMode)

	if err := cfg.Auth.Validate(); err != nil {
		return nil, closers, fmt.Errorf("invalid auth config: %w", err)
	}

	mainMetricsMW, err := metrics.NewMiddlewareWithConfig(metrics.MiddlewareConfig{
		Namespace:   "main",
		Registerer:  registry,
		IncludeHost: cfg.Metrics.IncludeHost,
	})
	if err != nil {
		return nil, closers, fmt.Errorf("creating main metrics middleware: %w", err)
	}
	engineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "main"))
	engine := gin.New()
	engine.Use(ginzap.GinzapWithConfig(engineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
		SkipPaths:  []string{"/healthz", "/readyz", "/metrics"},
	}))
	engine.Use(ginzap.RecoveryWithZap(engineLogger, true))
	engine.Use(metrics.GinMiddleware(mainMetricsMW))

	authEngine, err := buildAuthEngine(registry, cfg, closers)
	if err != nil {
		return nil, closers, fmt.Errorf("error creating http auth engine: %w", err)
	}

	engine.Any(AuthV1Path, authHandler(authEngine, cfg.Auth.HeaderSource))
	engine.Any(AuthV1Path+"/*uri", authHandler(authEngine, cfg.Auth.HeaderSource))
	if cfg.Server.AdminPort == 0 {
		addAdminEndpoints(registry, engine)
	}
	return engine, closers, nil
}

func buildSPOE(registry *prometheus.Registry, cfg config.Config) (*SPOEAgent, Closers, error) {
	closers := make(Closers, 0)
	gin.SetMode(gin.ReleaseMode)
	if err := cfg.Auth.Validate(); err != nil {
		return nil, closers, fmt.Errorf("invalid auth config: %w", err)
	}
	authEngine, err := buildAuthEngine(registry, cfg, closers)
	if err != nil {
		return nil, closers, fmt.Errorf("error creating spoe auth engine: %w", err)
	}
	agent := NewSPOEAgent(authEngine, cfg.Auth.AuthRequestTimeout)
	return agent, closers, nil
}

func buildEnvoy(registry *prometheus.Registry, cfg config.Config) (*EnvoyAuthorizationServer, Closers, error) {
	closers := make(Closers, 0)
	gin.SetMode(gin.ReleaseMode)
	if err := cfg.Auth.Validate(); err != nil {
		return nil, closers, fmt.Errorf("invalid auth config: %w", err)
	}
	authEngine, err := buildAuthEngine(registry, cfg, closers)
	if err != nil {
		return nil, closers, fmt.Errorf("error creating auth engine: %w", err)
	}
	authServer := NewEnvoyAuthorizationServer(authEngine, registry)
	return authServer, closers, nil
}

func buildAuthEngine(registry *prometheus.Registry, cfg config.Config, closers Closers) (*gin.Engine, error) {
	authMetricsMW, err := metrics.NewMiddlewareWithConfig(metrics.MiddlewareConfig{
		Namespace:   "auth",
		Registerer:  registry,
		IncludeHost: cfg.Metrics.IncludeHost,
	})
	if err != nil {
		return nil, fmt.Errorf("creating auth metrics middleware: %w", err)
	}

	authEngineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "auth"))
	authEngine := gin.New()
	authEngine.Use(ginzap.GinzapWithConfig(authEngineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
	}))
	authEngine.Use(ginzap.RecoveryWithZap(authEngineLogger, true))
	authEngine.Use(metrics.GinMiddleware(authMetricsMW))

	if cfg.Auth.JWTConfig.Enabled {
		verifier, err := jwt.NewJWTVerifier(context.Background(), cfg.Auth.JWTConfig)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT verifier: %w", err)
		}
		closers.Add(verifier)
		authEngine.Use(verifier.Middleware())
	}

	enforcer, err := newLifecycleEnforcer(&cfg.Casbin)
	if err != nil {
		return nil, fmt.Errorf("could not create enforcer: %w", err)
	}
	closers.Add(enforcer)

	var routeConfig *auth.RouteConfig
	if cfg.Auth.RouteConfigPath != "" {
		routeConfig, err = loadRouteConfig(cfg.Auth.RouteConfigPath)
		if err != nil {
			return nil, fmt.Errorf("error loading route config: %w", err)
		}
	} else {
		zlog.Warnf("auth-route-config-path is not provided")
		routeConfig = &auth.RouteConfig{}
	}
	auth.SetupRoutes(authEngine, routeConfig.Routes, enforcer.SyncedEnforcer)

	zlog.Infof("starting enforcer")
	err = enforcer.Start(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error starting enforcer: %w", err)
	}
	return authEngine, nil
}

func newRegistry() *prometheus.Registry {
	registerer := prometheus.NewRegistry()
	registerer.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return registerer
}

func buildAdminEngine(registry *prometheus.Registry) *gin.Engine {
	engineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "admin"))
	engine := gin.New()
	engine.Use(ginzap.GinzapWithConfig(engineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
		SkipPaths:  []string{"/healthz", "/readyz", "/metrics"},
	}))
	engine.Use(ginzap.RecoveryWithZap(engineLogger, true))
	addAdminEndpoints(registry, engine)
	return engine
}

func getAdminAddr(cfg config.Config) (string, error) {
	addr := cfg.Server.Addr
	if addr == "" {
		return "", errors.New("server address cannot be empty")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// handle cases like ":8080" or invalid formats
		if strings.HasPrefix(addr, ":") {
			host = ""
		} else {
			return "", fmt.Errorf("invalid server address %q: %w", addr, err)
		}
	}
	adminAddr := net.JoinHostPort(host, strconv.Itoa(cfg.Server.AdminPort))
	return adminAddr, nil
}

func addAdminEndpoints(registry *prometheus.Registry, engine *gin.Engine) {
	engine.GET("/healthz", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	engine.GET("/readyz", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	engine.GET("/metrics", metrics.NewHandlerWithConfig(metrics.HandlerConfig{
		Gatherer: registry,
	}))
}

func authHandler(authEngine *gin.Engine, authHeaderSource config.AuthHeaderSource) gin.HandlerFunc {
	return func(c *gin.Context) {
		reason, headers, err := forwardAuth(c, authEngine, authHeaderSource)
		if err == nil {
			c.String(http.StatusOK, reason)
			return
		}

		if errors.Is(err, ErrUnauthorized) {
			for key, values := range headers {
				for _, value := range values {
					c.Writer.Header().Add(key, value)
				}
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}
}

func Start(cfg config.Config) error {
	switch cfg.Server.Mode {
	case config.ServerModeHTTP:
		return StartHTTP(cfg)
	case config.ServerModeSPOE:
		return StartSPOE(cfg)
	case config.ServerModeEnvoy:
		return StartEnvoy(cfg)
	default:
		return fmt.Errorf("unsupported server mode: %s", cfg.Server.Mode)
	}
}

func StartHTTP(cfg config.Config) error {
	registry := newRegistry()
	engine, closers, err := buildEngine(registry, cfg)
	defer func() { _ = closers.Close() }()
	if err != nil {
		return fmt.Errorf("error building engine: %w", err)
	}
	var group run.Group
	addListenerServer(&group, cfg, engine.RunListener)
	if err = addAdminServer(&group, cfg, registry); err != nil {
		return err
	}
	return group.Run()
}

func StartSPOE(cfg config.Config) error {
	registry := newRegistry()
	agent, closers, err := buildSPOE(registry, cfg)
	defer func() { _ = closers.Close() }()
	if err != nil {
		return fmt.Errorf("error building agent: %w", err)
	}
	var group run.Group
	addListenerServer(&group, cfg, agent.RunListener)
	if err = addAdminServer(&group, cfg, registry); err != nil {
		return err
	}
	return group.Run()
}

func StartEnvoy(cfg config.Config) error {
	registry := newRegistry()
	authServer, closers, err := buildEnvoy(registry, cfg)
	defer func() { _ = closers.Close() }()
	if err != nil {
		return fmt.Errorf("error building envoy auth server: %w", err)
	}
	var group run.Group
	addListenerServer(&group, cfg, authServer.RunListener)
	if err = addAdminServer(&group, cfg, registry); err != nil {
		return err
	}
	return group.Run()
}

func addListenerServer(group *run.Group, cfg config.Config, runWithListener func(net.Listener) error) {
	var ln net.Listener
	group.Add(func() error {
		listener, err := buildListener(cfg.Server)
		if err != nil {
			return fmt.Errorf("error building listener: %w", err)
		}
		ln = listener

		msg := fmt.Sprintf("starting server (%s)", cfg.Server.Mode)
		if cfg.Server.TLS.Enable {
			msg = fmt.Sprintf("starting TLS server (%s)", cfg.Server.Mode)
		}
		zlog.Infof("%s on %s (version: %s)", msg, cfg.Server.Addr, getVersion())

		return runWithListener(ln)
	}, func(error) {
		if ln != nil {
			_ = ln.Close()
		}
	})
}

func addAdminServer(group *run.Group, cfg config.Config, registry *prometheus.Registry) error {
	if cfg.Server.AdminPort <= 0 {
		return nil
	}
	adminAddr, err := getAdminAddr(cfg)
	if err != nil {
		return fmt.Errorf("error getting admin address: %w", err)
	}
	adminEngine := buildAdminEngine(registry)

	group.Add(func() error {
		zlog.Infof("starting admin server %s", adminAddr)
		return adminEngine.Run(adminAddr)
	}, func(err error) {
	})
	return nil
}

func buildListener(cfg config.ServerConfig) (net.Listener, error) {
	//nolint:noctx
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("error listening on %s: %w", cfg.Addr, err)
	}
	if !cfg.TLS.Enable {
		return ln, nil
	}
	logger := slog.New(slogzap.Option{Logger: zlog.LogSink}.NewZapHandler())
	tlsConfig, err := tlsserverconfig.GetServerTLSConfig(logger, &cfg.TLS)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("error creating TLS server config: %w", err)
	}
	return tls.NewListener(ln, tlsConfig), nil
}

func getVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return config.Version
}

func loadRouteConfig(path string) (*auth.RouteConfig, error) {
	// #nosec G304 -- path is controlled and provided as config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg auth.RouteConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err = cfg.Validate(); err != nil {
		return nil, err
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("error marshalling route config: %w", err)
	}
	zlog.Infof("route config:\n" + string(b))
	return &cfg, nil
}

func forwardAuth(c *gin.Context, authEngine *gin.Engine, authHeaderSource config.AuthHeaderSource) (string, http.Header, error) {
	forwardedMethod, forwardedHost, forwardedUri, err := getForwardedTarget(c, authHeaderSource)
	if err != nil {
		return "", nil, err
	}
	lw := zlog.Logger.WithValues("method", forwardedMethod, "host", forwardedHost, "uri", forwardedUri)
	lw.V(1).Info("forward auth")

	req, err := http.NewRequestWithContext(c, forwardedMethod, forwardedUri, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.RemoteAddr = c.Request.RemoteAddr

	// copy all headers
	req.Header = c.Request.Header.Clone()

	// delete traefik headers
	req.Header.Del(HeaderForwardedMethod)
	req.Header.Del(HeaderForwardedProto)
	req.Header.Del(HeaderForwardedHost)
	req.Header.Del(HeaderForwardedURI)
	req.Header.Del(HeaderForwardedFor)
	// delete nginx headers
	req.Header.Del(HeaderOriginalMethod)
	req.Header.Del(HeaderOriginalURI)
	req.Header.Del(HeaderOriginalURL)

	// set original host
	req.Host = forwardedHost
	req.Header.Set(HeaderHost, forwardedHost)

	w := httptest.NewRecorder()
	authEngine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		lw.V(1).Info("forward auth rejected", "code", w.Code)
		if w.Code == http.StatusUnauthorized {
			resHeaders := make(http.Header)
			hv := w.Header().Values(HeaderWWWAuthenticate)
			if len(hv) > 0 {
				resHeaders.Add(HeaderWWWAuthenticate, hv[0])
			}
			return "", resHeaders, fmt.Errorf("%w: %s", ErrUnauthorized, w.Body.String())
		}
		return "", nil, errors.New(w.Body.String())
	}
	return w.Body.String(), nil, nil
}

func doForwardAuthHTTP(ctx context.Context, authEngine *gin.Engine, method, host, uri string, headers http.Header) (int, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, method, uri, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header = headers.Clone()
	req.Host = host
	req.Header.Set(HeaderHost, host)

	w := httptest.NewRecorder()
	authEngine.ServeHTTP(w, req)

	switch w.Code {
	case http.StatusOK:
		return http.StatusOK, nil, nil
	case http.StatusNotFound:
		return http.StatusNotFound, nil, nil
	case http.StatusUnauthorized:
		resHeaders := make(map[string]string)
		if hv := w.Header().Values(HeaderWWWAuthenticate); len(hv) > 0 {
			resHeaders[HeaderWWWAuthenticate] = hv[0]
		}
		return http.StatusUnauthorized, resHeaders, nil

	default:
		return http.StatusForbidden, nil, nil
	}
}

func getForwardedTarget(c *gin.Context, authHeaderSource config.AuthHeaderSource) (string, string, string, error) {
	// SECURITY NOTE:
	// In "auto" mode, this function attempts to resolve the request target from either
	// X-Forwarded-* or X-Original-* headers. The trusted reverse proxy (e.g., Traefik or Nginx)
	// MUST strip these headers from all incoming client requests before adding its own.
	// Otherwise, an attacker could inject forged headers and spoof the original request
	// method, host, or URI — potentially bypassing authentication or authorization logic.

	switch authHeaderSource {
	case config.AuthHeaderSourceForwarded:
		return getFromForwarded(c)
	case config.AuthHeaderSourceOriginal:
		return getFromOriginal(c)
	case config.AuthHeaderSourceRequest:
		return getFromRequest(c)
	case config.AuthHeaderSourceAuto:
		// try forwarded first, then original — current behavior
		if m, h, u, err := getFromForwarded(c); err == nil {
			return m, h, u, nil
		}
		if m, h, u, err := getFromOriginal(c); err == nil {
			return m, h, u, nil
		}
		return getFromRequest(c)
	default:
		return "", "", "", fmt.Errorf("unsupported header source %q", authHeaderSource)
	}
}

func getFromForwarded(c *gin.Context) (string, string, string, error) {
	method := c.GetHeader(HeaderForwardedMethod)
	host := c.GetHeader(HeaderForwardedHost)
	uri := c.GetHeader(HeaderForwardedURI)
	if method == "" || host == "" || uri == "" {
		return "", "", "", ErrMissingForwardAuthHeaders
	}
	return method, host, uri, nil
}

func getFromOriginal(c *gin.Context) (string, string, string, error) {
	method := c.GetHeader(HeaderOriginalMethod)
	uri := c.GetHeader(HeaderOriginalURI)
	host := ""
	if raw := c.GetHeader(HeaderOriginalURL); raw != "" {
		u, parseErr := url.Parse(raw)
		if parseErr != nil {
			return "", "", "", fmt.Errorf("invalid X-Original-URL: %w", parseErr)
		}
		host = u.Host
		if uri == "" {
			uri = u.RequestURI()
		}
	}
	if method == "" || host == "" || uri == "" {
		return "", "", "", ErrMissingForwardAuthHeaders
	}
	return method, host, uri, nil
}

func getFromRequest(c *gin.Context) (string, string, string, error) {
	method := c.Request.Method
	uri := strings.TrimPrefix(c.Request.RequestURI, AuthV1Path)
	if uri == "" {
		uri = "/" // treat bare /v1/auth as root
	}
	host := c.Request.Host
	if host == "" {
		return "", "", "", ErrInvalidRequestHeaders
	}
	return method, host, uri, nil
}
