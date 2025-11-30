// nolint: dogsled, canonicalheader
package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/negasus/haproxy-spoe-go/message"
	"github.com/negasus/haproxy-spoe-go/payload/kv"
)

func Test_getSPOEStringKV(t *testing.T) {
	kvStore := kv.NewKV()
	kvStore.Add("str", "value")
	kvStore.Add("int", 123)

	msg := &message.Message{
		Name: SPOEMessageName,
		KV:   kvStore,
	}

	t.Run("existing string key", func(t *testing.T) {
		got := getSPOEStringKV(msg, "str")
		assert.Equal(t, "value", got)
	})

	t.Run("missing key -> empty string", func(t *testing.T) {
		got := getSPOEStringKV(msg, "missing")
		assert.Empty(t, got)
	})

	t.Run("non-string value -> empty string", func(t *testing.T) {
		got := getSPOEStringKV(msg, "int")
		assert.Empty(t, got)
	})
}

func Test_getFromSPOE(t *testing.T) {
	t.Run("valid args", func(t *testing.T) {
		msg := message.AcquireMessage()
		msg.Name = SPOEMessageName
		msg.KV.Add(SPOEKVMethod, http.MethodPost)
		msg.KV.Add(SPOEKVHost, "example.com")
		msg.KV.Add(SPOEKVUri, "/path")

		method, host, uri, err := getFromSPOE(msg)
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, method)
		assert.Equal(t, "example.com", host)
		assert.Equal(t, "/path", uri)
	})

	t.Run("missing method", func(t *testing.T) {
		msg := message.AcquireMessage()
		msg.Name = SPOEMessageName
		msg.KV.Add(SPOEKVHost, "example.com")
		msg.KV.Add(SPOEKVUri, "/path")

		_, _, _, err := getFromSPOE(msg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingSPOEArgsHeaders)
	})

	t.Run("missing host", func(t *testing.T) {
		msg := message.AcquireMessage()
		msg.Name = SPOEMessageName
		msg.KV.Add(SPOEKVMethod, http.MethodGet)
		msg.KV.Add(SPOEKVUri, "/path")

		_, _, _, err := getFromSPOE(msg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingSPOEArgsHeaders)
	})

	t.Run("missing uri", func(t *testing.T) {
		msg := message.AcquireMessage()
		msg.Name = SPOEMessageName
		msg.KV.Add(SPOEKVMethod, http.MethodGet)
		msg.KV.Add(SPOEKVHost, "example.com")

		_, _, _, err := getFromSPOE(msg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingSPOEArgsHeaders)
	})
}

func Test_getSPOEHeaders_FiltersAndBuildsHeaderMap(t *testing.T) {
	kvStore := kv.NewKV()
	// valid headers
	kvStore.Add(SPOEHeaderPrefix+"X-Test", "abc")
	kvStore.Add(SPOEHeaderPrefix+"X-Multi", "one")
	kvStore.Add(SPOEHeaderPrefix+"X-Multi", "two")

	// invalid headers
	kvStore.Add(SPOEHeaderPrefix, "no-key")                      // empty key part
	kvStore.Add(SPOEHeaderPrefix+"X-Empty", "")                  // empty value
	kvStore.Add("X-Other", "should-be-ignored")                  // no prefix
	kvStore.Add(SPOEHeaderPrefix+"X-NonString", 42)              // non-string
	kvStore.Add(SPOEHeaderPrefix+"X-AlsoNonString", []byte("x")) // non-string

	msg := &message.Message{
		Name: SPOEMessageName,
		KV:   kvStore,
	}

	h := getSPOEHeaders(msg)
	require.Len(t, h, 2)

	assert.Equal(t, []string{"abc"}, h.Values("X-Test"))
	assert.Equal(t, []string{"one", "two"}, h.Values("X-Multi"))
	assert.Empty(t, h.Values("X-Empty"))
	assert.Empty(t, h.Values("X-Other"))
	assert.Empty(t, h.Values("X-NonString"))
}

func Test_SPOE_forwardAuthHTTP_HappyPath_Allow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var seen struct {
		method string
		uri    string
		host   string
		header http.Header
	}

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		seen.method = c.Request.Method
		seen.uri = c.Request.URL.RequestURI()
		seen.host = c.Request.Host
		seen.header = c.Request.Header.Clone()
		c.String(http.StatusOK, "allowed")
	})

	s := &SPOEAgent{
		authEngine:  authEngine,
		authTimeout: 2 * time.Second,
	}

	headers := make(http.Header)
	headers.Set("X-Custom", "abc")
	headers.Set(HeaderForwardedFor, "1.2.3.4") // to verify it is just passed through

	code, resHeaders, err := s.forwardAuthHTTP(context.Background(), http.MethodPost, "svc.local", "/target/path?q=1", headers)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, code)
	assert.Empty(t, resHeaders)

	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "/target/path?q=1", seen.uri)
	assert.Equal(t, "svc.local", seen.host)

	// Host header should be set
	assert.Equal(t, "svc.local", seen.header.Get(HeaderHost))
	// Existing headers should be preserved
	assert.Equal(t, "abc", seen.header.Get("X-Custom"))
	assert.Equal(t, "1.2.3.4", seen.header.Get(HeaderForwardedFor))
}

func Test_SPOE_forwardAuthHTTP_Unauthorized_ReturnsWWWAuthenticateHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const wwwAuth = `Bearer realm="https://issuer.example.internal", error="invalid_token"`

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		c.Header(HeaderWWWAuthenticate, wwwAuth)
		c.Status(http.StatusUnauthorized)
	})

	s := &SPOEAgent{
		authEngine:  authEngine,
		authTimeout: 2 * time.Second,
	}

	headers := make(http.Header)
	code, resHeaders, err := s.forwardAuthHTTP(context.Background(), http.MethodGet, "svc.local", "/some/resource", headers)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, code)
	require.Len(t, resHeaders, 1)
	assert.Equal(t, wwwAuth, resHeaders[HeaderWWWAuthenticate])
}

func Test_SPOE_forwardAuthHTTP_NonOKNon401_MapsToForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		c.String(http.StatusTeapot, "i'm a teapot") // any non-200, non-401
	})

	s := &SPOEAgent{
		authEngine:  authEngine,
		authTimeout: 2 * time.Second,
	}

	headers := make(http.Header)
	code, resHeaders, err := s.forwardAuthHTTP(context.Background(), http.MethodGet, "svc.local", "/some/resource", headers)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, code)
	assert.Empty(t, resHeaders)
}

func Test_SPOE_performForwardAuth_HappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	s := &SPOEAgent{
		authEngine:  authEngine,
		authTimeout: 2 * time.Second,
	}

	kvStore := kv.NewKV()
	kvStore.Add(SPOEKVMethod, http.MethodGet)
	kvStore.Add(SPOEKVHost, "svc.local")
	kvStore.Add(SPOEKVUri, "/ok")

	// include one SPOE header to verify it's forwarded to forwardAuthHTTP
	kvStore.Add(SPOEHeaderPrefix+"X-From-SPOE", "yes")

	msg := &message.Message{
		Name: SPOEMessageName,
		KV:   kvStore,
	}

	code, headers, err := s.performForwardAuth(context.Background(), msg)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, code)
	assert.Empty(t, headers)
}

func Test_SPOE_performForwardAuth_MissingArgs_Error(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authEngine := gin.New()
	s := &SPOEAgent{
		authEngine:  authEngine,
		authTimeout: 2 * time.Second,
	}

	kvStore := kv.NewKV()
	// no method/host/uri
	msg := &message.Message{
		Name: SPOEMessageName,
		KV:   kvStore,
	}

	_, _, err := s.performForwardAuth(context.Background(), msg)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingSPOEArgsHeaders)
}

func Test_setSPOEResponse_SetsAllowStatusAndHeaders(t *testing.T) {
	req := &request.Request{
		Actions: action.Actions{},
	}

	headers := map[string]string{
		"X-Ok":   "v1",
		"":       "ignored",
		"X-Also": "v2",
	}

	// should not panic
	setSPOEResponse(req, http.StatusOK, headers)
}

func Test_LoggerFunc_AdaptsToLoggerInterface(t *testing.T) {
	var called bool
	var gotFmt string
	var gotArgs []interface{}

	fn := LoggerFunc(func(format string, args ...interface{}) {
		called = true
		gotFmt = format
		gotArgs = args
	})

	fn.Errorf("hello %s %d", "world", 42)

	assert.True(t, called)
	assert.Equal(t, "hello %s %d", gotFmt)
	require.Len(t, gotArgs, 2)
	assert.Equal(t, "world", gotArgs[0])
	assert.Equal(t, 42, gotArgs[1])
}

func newTestSPOERequest(method, host, uri string, headers map[string]string) *request.Request {
	msg := message.AcquireMessage()
	msg.Name = SPOEMessageName

	// Add required SPOE key-value pairs
	msg.KV.Add(SPOEKVMethod, method)
	msg.KV.Add(SPOEKVHost, host)
	msg.KV.Add(SPOEKVUri, uri)

	// Add headers with the header. prefix
	for k, v := range headers {
		msg.KV.Add(SPOEHeaderPrefix+k, v)
	}

	messages := message.NewMessages()
	*messages = append(*messages, msg)

	actions := make(action.Actions, 0)

	req := &request.Request{
		Messages: messages,
		Actions:  actions,
		EngineID: "test-engine",
		StreamID: 1,
		FrameID:  1,
	}

	return req
}

func Test_SPOEAgent_handleRequest_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create auth engine that allows all requests
	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		c.String(http.StatusOK, "allowed")
	})

	agent := NewSPOEAgent(authEngine, 5*time.Second)

	req := newTestSPOERequest(
		http.MethodGet,
		"svc.local",
		"/api/resource",
		map[string]string{
			"Authorization": "Bearer valid-token",
			"X-Custom":      "value",
		},
	)

	agent.handleRequest(req)

	// Check that allow=1 and status=200
	actions := req.Actions
	require.Len(t, actions, 2, "expected 2 actions: allow and status")

	// Find allow action
	var allowAction, statusAction *action.Action
	for i := range actions {
		if actions[i].Name == SPOEVarAllow {
			allowAction = &actions[i]
		}
		if actions[i].Name == SPOEVarStatus {
			statusAction = &actions[i]
		}
	}

	require.NotNil(t, allowAction, "allow action should be set")
	assert.Equal(t, action.TypeSetVar, allowAction.Type)
	assert.Equal(t, action.ScopeTransaction, allowAction.Scope)
	assert.Equal(t, 1, allowAction.Value)

	require.NotNil(t, statusAction, "status action should be set")
	assert.Equal(t, action.TypeSetVar, statusAction.Type)
	assert.Equal(t, action.ScopeTransaction, statusAction.Scope)
	assert.Equal(t, http.StatusOK, statusAction.Value)
}

func Test_SPOEAgent_handleRequest_Forbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create auth engine that denies all requests
	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		c.String(http.StatusForbidden, "forbidden")
	})

	agent := NewSPOEAgent(authEngine, 5*time.Second)

	req := newTestSPOERequest(
		http.MethodPost,
		"svc.local",
		"/api/admin",
		map[string]string{
			"Authorization": "Bearer invalid-token",
		},
	)

	agent.handleRequest(req)

	// Check that allow=0 and status=403
	actions := req.Actions
	require.Len(t, actions, 2, "expected 2 actions: allow and status")

	// Find allow action
	var allowAction, statusAction *action.Action
	for i := range actions {
		if actions[i].Name == SPOEVarAllow {
			allowAction = &actions[i]
		}
		if actions[i].Name == SPOEVarStatus {
			statusAction = &actions[i]
		}
	}

	require.NotNil(t, allowAction, "allow action should be set")
	assert.Equal(t, action.TypeSetVar, allowAction.Type)
	assert.Equal(t, action.ScopeTransaction, allowAction.Scope)
	assert.Equal(t, 0, allowAction.Value)

	require.NotNil(t, statusAction, "status action should be set")
	assert.Equal(t, action.TypeSetVar, statusAction.Type)
	assert.Equal(t, action.ScopeTransaction, statusAction.Scope)
	assert.Equal(t, http.StatusForbidden, statusAction.Value)
}

func Test_SPOEAgent_handleRequest_Unauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create auth engine that returns 401
	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		c.Header(HeaderWWWAuthenticate, `Bearer realm="example.com"`)
		c.String(http.StatusUnauthorized, "unauthorized")
	})

	agent := NewSPOEAgent(authEngine, 5*time.Second)

	req := newTestSPOERequest(
		http.MethodGet,
		"svc.local",
		"/api/protected",
		nil, // no auth header
	)

	agent.handleRequest(req)

	// Check that allow=0 and status=401
	actions := req.Actions
	require.GreaterOrEqual(t, len(actions), 3, "expected at least 3 actions: allow, status, and WWW-Authenticate header")

	// Find actions
	var allowAction, statusAction, wwwAuthAction *action.Action
	for i := range actions {
		if actions[i].Name == SPOEVarAllow {
			allowAction = &actions[i]
		}
		if actions[i].Name == SPOEVarStatus {
			statusAction = &actions[i]
		}
		if actions[i].Name == spoeRespHeaderVar(HeaderWWWAuthenticate) {
			wwwAuthAction = &actions[i]
		}
	}

	require.NotNil(t, allowAction, "allow action should be set")
	assert.Equal(t, action.TypeSetVar, allowAction.Type)
	assert.Equal(t, action.ScopeTransaction, allowAction.Scope)
	assert.Equal(t, 0, allowAction.Value)

	require.NotNil(t, statusAction, "status action should be set")
	assert.Equal(t, action.TypeSetVar, statusAction.Type)
	assert.Equal(t, action.ScopeTransaction, statusAction.Scope)
	assert.Equal(t, http.StatusUnauthorized, statusAction.Value)

	// Check that WWW-Authenticate header is set
	require.NotNil(t, wwwAuthAction, "WWW-Authenticate header action should be set")
	assert.Equal(t, action.TypeSetVar, wwwAuthAction.Type)
	assert.Equal(t, action.ScopeTransaction, wwwAuthAction.Scope)
	assert.Equal(t, `Bearer realm="example.com"`, wwwAuthAction.Value)
}

func Test_SPOEAgent_handleRequest_MissingMessageName(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authEngine := gin.New()
	agent := NewSPOEAgent(authEngine, 5*time.Second)

	// Create request with wrong message name
	msg := message.AcquireMessage()
	msg.Name = "wrong-message-name"
	msg.KV.Add(SPOEKVMethod, http.MethodGet)
	msg.KV.Add(SPOEKVHost, "svc.local")
	msg.KV.Add(SPOEKVUri, "/test")

	messages := message.NewMessages()
	*messages = append(*messages, msg)

	actions := make(action.Actions, 0)

	req := &request.Request{
		Messages: messages,
		Actions:  actions,
		EngineID: "test-engine",
		StreamID: 1,
		FrameID:  1,
	}

	agent.handleRequest(req)

	// Should return forbidden when message not found
	actions = req.Actions
	require.Len(t, actions, 2, "expected 2 actions: allow and status")

	var allowAction, statusAction *action.Action
	for i := range actions {
		if actions[i].Name == SPOEVarAllow {
			allowAction = &actions[i]
		}
		if actions[i].Name == SPOEVarStatus {
			statusAction = &actions[i]
		}
	}

	require.NotNil(t, allowAction)
	assert.Equal(t, 0, allowAction.Value)

	require.NotNil(t, statusAction)
	assert.Equal(t, http.StatusForbidden, statusAction.Value)
}

func Test_SPOEAgent_handleRequest_MissingSPOEArgs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authEngine := gin.New()
	agent := NewSPOEAgent(authEngine, 5*time.Second)

	// Create request missing required fields
	msg := message.AcquireMessage()
	msg.Name = SPOEMessageName
	msg.KV.Add(SPOEKVMethod, http.MethodGet)
	// Missing host and uri

	messages := message.NewMessages()
	*messages = append(*messages, msg)

	actions := make(action.Actions, 0)

	req := &request.Request{
		Messages: messages,
		Actions:  actions,
		EngineID: "test-engine",
		StreamID: 1,
		FrameID:  1,
	}

	agent.handleRequest(req)

	// Should return forbidden when required args are missing
	actions = req.Actions
	require.Len(t, actions, 2, "expected 2 actions: allow and status")

	var allowAction, statusAction *action.Action
	for i := range actions {
		if actions[i].Name == SPOEVarAllow {
			allowAction = &actions[i]
		}
		if actions[i].Name == SPOEVarStatus {
			statusAction = &actions[i]
		}
	}

	require.NotNil(t, allowAction)
	assert.Equal(t, 0, allowAction.Value)

	require.NotNil(t, statusAction)
	assert.Equal(t, http.StatusForbidden, statusAction.Value)
}

func Test_SPOEAgent_handleRequest_HeadersForwarded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var seenHeaders map[string][]string
	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		seenHeaders = c.Request.Header
		c.String(http.StatusOK, "ok")
	})

	agent := NewSPOEAgent(authEngine, 5*time.Second)

	req := newTestSPOERequest(
		http.MethodGet,
		"svc.local",
		"/test",
		map[string]string{
			"Authorization": "Bearer token123",
			"X-Request-ID":  "req-456",
			"User-Agent":    "TestAgent/1.0",
		},
	)

	agent.handleRequest(req)

	// Verify headers were forwarded
	assert.Equal(t, "Bearer token123", seenHeaders["Authorization"][0])
	assert.Equal(t, "req-456", seenHeaders["X-Request-Id"][0])
	assert.Equal(t, "TestAgent/1.0", seenHeaders["User-Agent"][0])
	assert.Equal(t, "svc.local", seenHeaders[HeaderHost][0])
}
