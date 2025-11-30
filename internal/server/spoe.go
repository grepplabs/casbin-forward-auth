package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/grepplabs/loggo/zlog"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/message"
	"github.com/negasus/haproxy-spoe-go/request"
)

var (
	ErrMissingSPOEArgsHeaders = errors.New("missing spoe args: method, host or uri; verify the spoe-message configuration")
)

const (
	SPOEMessageName      = "forward-auth"
	SPOEHeaderPrefix     = "header."
	SPOERespHeaderPrefix = "resp_header."
	SPOEVarAllow         = "allow"
	SPOEVarStatus        = "status"

	SPOEKVMethod = "method"
	SPOEKVHost   = "host"
	SPOEKVUri    = "uri"
)

// SPOEAgent handles SPOE protocol requests
type SPOEAgent struct {
	agent       *agent.Agent
	authEngine  *gin.Engine
	authTimeout time.Duration
}

func NewSPOEAgent(authEngine *gin.Engine, authTimeout time.Duration) *SPOEAgent {
	s := &SPOEAgent{
		authEngine:  authEngine,
		authTimeout: authTimeout,
	}
	s.agent = agent.New(s.handleRequest, LoggerFunc(zlog.Errorf))
	return s
}

func (s *SPOEAgent) RunListener(ln net.Listener) error {
	return s.agent.Serve(ln)
}

func (s *SPOEAgent) handleRequest(req *request.Request) {
	msg, err := req.Messages.GetByName(SPOEMessageName)
	if err != nil {
		zlog.Errorf("spoe message '%s' not found: engineId=%q streamId=%d frameId=%d", SPOEMessageName, req.EngineID, req.StreamID, req.FrameID)
		setSPOEResponse(req, http.StatusForbidden, nil)
		return
	}

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if s.authTimeout <= 0 {
		ctx, cancel = context.Background(), func() {} // No-op cancel function
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), s.authTimeout)
	}
	defer cancel()

	code, headers, err := s.performForwardAuth(ctx, msg)
	if err != nil {
		zlog.Errorf("spoe forward auth failed: %v", err)
		setSPOEResponse(req, http.StatusForbidden, nil)
		return
	}
	setSPOEResponse(req, code, headers)
}

func (s *SPOEAgent) performForwardAuth(ctx context.Context, msg *message.Message) (int, map[string]string, error) {
	forwardedMethod, forwardedHost, forwardedUri, err := getFromSPOE(msg)
	if err != nil {
		return 0, nil, err
	}

	lw := zlog.Logger.WithValues("method", forwardedMethod, "host", forwardedHost, "uri", forwardedUri)
	lw.V(1).Info("spoe forward auth")

	code, headers, err := s.forwardAuthHTTP(ctx, forwardedMethod, forwardedHost, forwardedUri, getSPOEHeaders(msg))
	if err == nil && code != http.StatusOK {
		lw.V(1).Info("spoe forward auth rejected", "code", code)
	}
	return code, headers, err
}

func (s *SPOEAgent) forwardAuthHTTP(ctx context.Context, method, host, uri string, headers http.Header) (int, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, method, uri, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header = headers.Clone()
	req.Host = host
	req.Header.Set(HeaderHost, host)

	w := httptest.NewRecorder()
	s.authEngine.ServeHTTP(w, req)

	switch w.Code {
	case http.StatusOK:
		return http.StatusOK, nil, nil

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

func setSPOEResponse(req *request.Request, code int, headers map[string]string) {
	allow := 0
	if code == http.StatusOK {
		allow = 1
	}
	req.Actions.SetVar(action.ScopeTransaction, SPOEVarAllow, allow)
	req.Actions.SetVar(action.ScopeTransaction, SPOEVarStatus, code)

	if len(headers) == 0 {
		return
	}
	for header, value := range headers {
		// set only when header key is non-empty
		if header == "" {
			continue
		}
		req.Actions.SetVar(action.ScopeTransaction, spoeRespHeaderVar(header), value)
	}
}

func spoeRespHeaderVar(header string) string {
	return SPOERespHeaderPrefix + strings.ReplaceAll(strings.ToLower(header), "-", "_")
}

func getSPOEHeaders(msg *message.Message) http.Header {
	headers := make(http.Header)
	for _, item := range msg.KV.Data() {
		if !strings.HasPrefix(item.Name, SPOEHeaderPrefix) {
			continue
		}
		value, ok := item.Value.(string)
		if !ok || value == "" {
			continue
		}
		key := item.Name[len(SPOEHeaderPrefix):]
		if key == "" {
			continue
		}
		headers.Add(key, value)
	}
	return headers
}

func getFromSPOE(msg *message.Message) (string, string, string, error) {
	method := getSPOEStringKV(msg, SPOEKVMethod)
	host := getSPOEStringKV(msg, SPOEKVHost)
	uri := getSPOEStringKV(msg, SPOEKVUri)

	if method == "" || host == "" || uri == "" {
		return "", "", "", ErrMissingSPOEArgsHeaders
	}
	return method, host, uri, nil
}

func getSPOEStringKV(mes *message.Message, key string) string {
	v, ok := mes.KV.Get(key)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// LoggerFunc adapts a function to the agent's Logger interface
type LoggerFunc func(format string, args ...interface{})

func (f LoggerFunc) Errorf(format string, args ...interface{}) {
	f(format, args...)
}
