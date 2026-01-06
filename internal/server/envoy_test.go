// nolint: protogetter
package server

import (
	"context"
	"net/http"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func Test_httpHeaderFromEnvoyHeaders(t *testing.T) {
	t.Run("converts and canonicalizes headers", func(t *testing.T) {
		in := map[string]string{
			"content-type": "application/json",
			"x-foo":        "bar",
		}

		got := httpHeaderFromEnvoyHeaders(in)

		assert.Equal(t, http.Header{
			"Content-Type": []string{"application/json"},
			"X-Foo":        []string{"bar"},
		}, got)
	})

	t.Run("skips empty key", func(t *testing.T) {
		in := map[string]string{
			"":      "nope",
			"x-ok":  "yes",
			"X-OK2": "yes2",
		}

		got := httpHeaderFromEnvoyHeaders(in)

		_, hasEmpty := got[""]
		assert.False(t, hasEmpty)

		assert.Equal(t, []string{"yes"}, got["X-Ok"])
		assert.Equal(t, []string{"yes2"}, got["X-Ok2"])
	})

	t.Run("skips http2 pseudo headers", func(t *testing.T) {
		in := map[string]string{
			":method": "GET",
			":path":   "/",
			"host":    "example.com",
		}

		got := httpHeaderFromEnvoyHeaders(in)

		assert.Empty(t, got[":method"])
		assert.Empty(t, got[":path"])
		assert.Equal(t, []string{"example.com"}, got["Host"])
	})

	t.Run("sets single value slice", func(t *testing.T) {
		in := map[string]string{
			"x-multi": "a,b,c",
		}

		got := httpHeaderFromEnvoyHeaders(in)

		assert.Equal(t, []string{"a,b,c"}, got["X-Multi"])
	})
}

func Test_toEnvoyHeaders(t *testing.T) {
	t.Run("nil when input map is nil", func(t *testing.T) {
		var in map[string]string
		got := toEnvoyHeaders(in)
		assert.Nil(t, got)
	})

	t.Run("nil when input map is empty", func(t *testing.T) {
		got := toEnvoyHeaders(map[string]string{})
		assert.Nil(t, got)
	})

	t.Run("skips empty key", func(t *testing.T) {
		in := map[string]string{
			"":      "ignored",
			"X-Ok":  "v1",
			"X-Ok2": "v2",
		}

		got := toEnvoyHeaders(in)
		require.Len(t, got, 2)

		m := envoyHeaderValueOptionsToMap(got)

		assert.Equal(t, "v1", m["X-Ok"])
		assert.Equal(t, "v2", m["X-Ok2"])

		for _, h := range got {
			require.NotNil(t, h)
			assert.Equal(t, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, h.AppendAction)
			require.NotNil(t, h.Header)
			assert.NotEmpty(t, h.Header.Key)
		}
	})

	t.Run("builds HeaderValueOptions with overwrite action", func(t *testing.T) {
		in := map[string]string{
			"X-Test": "abc",
			"X-Two":  "def",
		}

		got := toEnvoyHeaders(in)
		require.Len(t, got, 2)

		m := envoyHeaderValueOptionsToMap(got)
		assert.Equal(t, "abc", m["X-Test"])
		assert.Equal(t, "def", m["X-Two"])

		for _, h := range got {
			require.NotNil(t, h)
			require.NotNil(t, h.Header)
			assert.Equal(t, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, h.AppendAction)
		}
	})
}

func Test_authorizationServer_Check(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type seenReq struct {
		method  string
		host    string
		uri     string
		headers http.Header
	}
	var seen seenReq

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		seen.method = c.Request.Method
		seen.host = c.Request.Host
		seen.uri = c.Request.URL.RequestURI()
		seen.headers = c.Request.Header.Clone()

		switch c.Request.URL.Path {
		case "/ok":
			c.Status(http.StatusOK)
		case "/notfound":
			c.Status(http.StatusNotFound)
		case "/unauthorized":
			c.Header(HeaderWWWAuthenticate, `Bearer realm="example.com"`)
			c.Status(http.StatusUnauthorized)
		case "/forbidden":
			c.Status(http.StatusForbidden)
		default:
			c.Status(http.StatusTeapot)
		}
	})

	type envoyReq struct {
		method  string
		host    string
		path    string
		headers map[string]string
	}

	type wantResp struct {
		grpcCode codes.Code
		ok       bool

		deniedHTTP typev3.StatusCode
		msg        string
		body       string

		headers map[string]string // expected response headers (ok/denied)
	}

	type wantSeen struct {
		method string
		host   string
		uri    string
	}

	type want struct {
		resp wantResp
		seen wantSeen
	}
	req := func(method, host, path string, headers map[string]string) envoyReq {
		return envoyReq{method: method, host: host, path: path, headers: headers}
	}
	seenWant := func(method, host, uri string) wantSeen {
		return wantSeen{method: method, host: host, uri: uri}
	}
	allow := func(grpcCode codes.Code) want {
		return want{
			resp: wantResp{grpcCode: grpcCode, ok: true, headers: map[string]string{}},
		}
	}
	deny := func(deniedHTTP typev3.StatusCode, msg, body string) want {
		return want{
			resp: wantResp{
				grpcCode:   codes.PermissionDenied,
				ok:         false,
				deniedHTTP: deniedHTTP,
				msg:        msg,
				body:       body,
				headers:    map[string]string{},
			},
		}
	}

	denyWithHeaders := func(deniedHTTP typev3.StatusCode, msg, body string, headers map[string]string) want {
		w := deny(deniedHTTP, msg, body)
		w.resp.headers = headers
		return w
	}

	withSeen := func(w want, s wantSeen) want {
		w.seen = s
		return w
	}

	tests := []struct {
		name string
		in   envoyReq
		want want
	}{
		{
			name: "200 OK -> allow",
			in:   req(http.MethodGet, "svc.local", "/ok", map[string]string{"x-custom": "abc", ":method": "GET"}),
			want: withSeen(
				allow(codes.OK),
				seenWant(http.MethodGet, "svc.local", "/ok"),
			),
		},
		{
			name: "404 -> deny forbidden not found",
			in:   req(http.MethodGet, "svc.local", "/notfound", nil),
			want: withSeen(
				deny(typev3.StatusCode_Forbidden, "not found", errorBodyNotFound),
				seenWant(http.MethodGet, "svc.local", "/notfound"),
			),
		},
		{
			name: "401 -> deny unauthorized + WWW-Authenticate returned",
			in:   req(http.MethodGet, "svc.local", "/unauthorized", nil),
			want: withSeen(
				denyWithHeaders(
					typev3.StatusCode_Unauthorized,
					"unauthorized",
					errorBodyRejected,
					map[string]string{HeaderWWWAuthenticate: `Bearer realm="example.com"`},
				),
				seenWant(http.MethodGet, "svc.local", "/unauthorized"),
			),
		},
		{
			name: "403 -> deny forbidden",
			in:   req(http.MethodPost, "svc.local", "/forbidden", nil),
			want: withSeen(
				deny(typev3.StatusCode_Forbidden, "forbidden", errorBodyRejected),
				seenWant(http.MethodPost, "svc.local", "/forbidden"),
			),
		},
		{
			name: "default -> deny forbidden",
			in:   req(http.MethodGet, "svc.local", "/teapot", nil),
			want: withSeen(
				deny(typev3.StatusCode_Forbidden, "forbidden", errorBodyRejected),
				seenWant(http.MethodGet, "svc.local", "/teapot"),
			),
		},
		{
			name: "host empty -> fallback to :authority",
			in:   req(http.MethodGet, "", "/ok", map[string]string{":authority": "authority.local"}),
			want: withSeen(
				allow(codes.OK),
				seenWant(http.MethodGet, "authority.local", "/ok"),
			),
		},
		{
			name: "host empty and no :authority -> fallback to host header",
			in:   req(http.MethodGet, "", "/ok", map[string]string{"host": "hosthdr.local"}),
			want: withSeen(
				allow(codes.OK),
				seenWant(http.MethodGet, "hosthdr.local", "/ok"),
			),
		},
		{
			name: "missing method -> denied forbidden with error text",
			in:   req("", "svc.local", "/ok", nil),
			want: deny(
				typev3.StatusCode_Forbidden,
				`missing required headers for forward auth: method="" host="svc.local"`,
				`missing required headers for forward auth: method="" host="svc.local"`,
			),
		},
		{
			name: "empty path -> defaults to /",
			in:   req(http.MethodGet, "svc.local", "", nil),
			want: withSeen(
				deny(typev3.StatusCode_Forbidden, "forbidden", errorBodyRejected),
				seenWant(http.MethodGet, "svc.local", "/"),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen = seenReq{} // reset

			r := makeEnvoyCheckRequest(tt.in)
			authSrv := &authorizationServer{authEngine: authEngine}
			resp, err := authSrv.Check(context.Background(), r)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Status)

			assert.Equal(t, int32(tt.want.resp.grpcCode), resp.Status.Code)

			if tt.want.resp.ok {
				ok := resp.GetOkResponse()
				require.NotNil(t, ok)
				gotHdr := envoyHeaderValueOptionsToMap(ok.Headers)
				assertHeadersSubset(t, tt.want.resp.headers, gotHdr)
			} else {
				denied := resp.GetDeniedResponse()
				require.NotNil(t, denied)
				require.NotNil(t, denied.Status)

				assert.Equal(t, tt.want.resp.deniedHTTP, denied.Status.Code)
				assert.Equal(t, tt.want.resp.msg, resp.Status.Message)
				assert.Equal(t, tt.want.resp.body, denied.Body)

				gotHdr := envoyHeaderValueOptionsToMap(denied.Headers)
				assertHeadersSubset(t, tt.want.resp.headers, gotHdr)
			}

			// Validate what reached gin only when expected.
			if tt.want.seen.method != "" || tt.want.seen.host != "" || tt.want.seen.uri != "" {
				assert.Equal(t, tt.want.seen.method, seen.method)
				assert.Equal(t, tt.want.seen.host, seen.host)
				assert.Equal(t, tt.want.seen.uri, seen.uri)

				// Pseudo headers must never appear as http.Header keys.
				for k := range tt.in.headers {
					if k == "" || k[0] == ':' {
						assert.Empty(t, seen.headers[k])
					}
				}
			}
		})
	}
}

func makeEnvoyCheckRequest(in struct {
	method  string
	host    string
	path    string
	headers map[string]string
}) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  in.method,
					Host:    in.host,
					Path:    in.path,
					Headers: in.headers,
				},
			},
		},
	}
}

func envoyHeaderValueOptionsToMap(in []*corev3.HeaderValueOption) map[string]string {
	out := map[string]string{}
	for _, h := range in {
		if h == nil || h.Header == nil || h.Header.Key == "" {
			continue
		}
		out[h.Header.Key] = h.Header.Value
	}
	return out
}

func assertHeadersSubset(t *testing.T, want, got map[string]string) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	for k, v := range want {
		assert.Equal(t, v, got[k], "header %q mismatch", k)
	}
}
