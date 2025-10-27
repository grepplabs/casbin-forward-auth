// nolint: funlen
package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetValue_URL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type tc struct {
		name   string
		rawURL string
		param  ParamConfig
		want   string
	}

	tests := []tc{
		{
			name:   "full URL without query is returned",
			rawURL: "https://example.com/api/v1/devices/42?limit=10&offset=2",
			param: ParamConfig{
				Source: ParamSourceURL,
				Name:   "url",
			},
			want: "https://example.com/api/v1/devices/42",
		},
		{
			name:   "url with no query stays the same",
			rawURL: "https://example.com/plain/path",
			param: ParamConfig{
				Source: ParamSourceURL,
				Name:   "url",
			},
			want: "https://example.com/plain/path",
		},
		{
			name:   "default is not used because URL is never empty",
			rawURL: "https://example.com/x",
			param: ParamConfig{
				Source:  ParamSourceURL,
				Name:    "url",
				Default: "should-not-be-used",
			},
			want: "https://example.com/x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithURL(t, "GET", tt.rawURL)
			got, err := getValue(c, tt.param)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetValue_URLPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type tc struct {
		name   string
		rawURL string
		param  ParamConfig
		want   string
	}

	tests := []tc{
		{
			name:   "returns only the path, ignores query",
			rawURL: "https://example.com/api/v1/projects/abc-123/items?foo=bar",
			param: ParamConfig{
				Source: ParamSourceURLPath,
				Name:   "urlPath",
			},
			want: "/api/v1/projects/abc-123/items",
		},
		{
			name:   "root path",
			rawURL: "https://example.com/",
			param: ParamConfig{
				Source: ParamSourceURLPath,
				Name:   "urlPath",
			},
			want: "/",
		},
		{
			name:   "root path for empty path",
			rawURL: "https://example.com",
			param: ParamConfig{
				Source: ParamSourceURLPath,
				Name:   "urlPath",
			},
			want: "/",
		},
		{
			name:   "no default used for non-empty path",
			rawURL: "https://example.com/a/b",
			param: ParamConfig{
				Source:  ParamSourceURLPath,
				Name:    "urlPath",
				Default: "/should/not/use",
			},
			want: "/a/b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithURL(t, "GET", tt.rawURL)
			got, err := getValue(c, tt.param)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetValue_Path(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type tc struct {
		name    string
		key     string
		val     string
		param   ParamConfig
		want    string
		wantErr string
	}

	tests := []tc{
		{
			name: "id present",
			key:  "id",
			val:  "42",
			param: ParamConfig{
				Source: ParamSourcePath,
				Name:   "id",
			},
			want: "42",
		},
		{
			name: "uses Default when empty in path",
			key:  "role",
			val:  "",
			param: ParamConfig{
				Source:  ParamSourcePath,
				Name:    "role",
				Default: "guest",
			},
			want: "guest",
		},
		{
			name: "value missing when not provided and no default",
			key:  "",
			val:  "",
			param: ParamConfig{
				Source: ParamSourcePath,
				Name:   "unknown",
			},
			wantErr: "value missing unknown",
		},
		{
			name: "empty without default -> error",
			key:  "empty",
			val:  "",
			param: ParamConfig{
				Source: ParamSourcePath,
				Name:   "empty",
			},
			wantErr: "value missing empty",
		},
		{
			name: "Expr overrides Name when set",
			key:  "project_id",
			val:  "abc-123",
			param: ParamConfig{
				Source: ParamSourcePath,
				Name:   "ignoredName",
				Expr:   "project_id",
			},
			want: "abc-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithPathParam(t, tt.key, tt.val)
			got, err := getValue(c, tt.param)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetValue_Query(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type tc struct {
		name    string
		rawQ    string
		param   ParamConfig
		want    string
		wantErr string
	}

	tests := []tc{
		{
			name: "simple present",
			rawQ: "id=42",
			param: ParamConfig{
				Source: ParamSourceQuery,
				Name:   "id",
			},
			want: "42",
		},
		{
			name: "missing -> error",
			rawQ: "",
			param: ParamConfig{
				Source: ParamSourceQuery,
				Name:   "id",
			},
			wantErr: "value missing id",
		},
		{
			name: "empty value uses Default",
			rawQ: "role=",
			param: ParamConfig{
				Source:  ParamSourceQuery,
				Name:    "role",
				Default: "guest",
			},
			want: "guest",
		},
		{
			name: "empty value without default -> error",
			rawQ: "token=",
			param: ParamConfig{
				Source: ParamSourceQuery,
				Name:   "token",
			},
			wantErr: "value missing token",
		},
		{
			name: "Expr overrides Name",
			rawQ: "project_id=abc-123",
			param: ParamConfig{
				Source: ParamSourceQuery,
				Name:   "ignored",
				Expr:   "project_id", // assumes ParamConfig.Key() prefers Expr
			},
			want: "abc-123",
		},
		{
			name: "multiple values -> first one is used",
			rawQ: "id=first&id=second",
			param: ParamConfig{
				Source: ParamSourceQuery,
				Name:   "id",
			},
			want: "first",
		},
		{
			name: "key with dot is literal (not path expr)",
			rawQ: "user.name=mike",
			param: ParamConfig{
				Source: ParamSourceQuery,
				Name:   "user.name",
			},
			want: "mike",
		},
		{
			name: "URL encoded value",
			rawQ: "q=hello%20world",
			param: ParamConfig{
				Source: ParamSourceQuery,
				Name:   "q",
			},
			want: "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithQuery(t, tt.rawQ)
			got, err := getValue(c, tt.param)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetValue_Header(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type tc struct {
		name    string
		build   func(*map[string][]string)
		param   ParamConfig
		want    string
		wantErr string
	}

	tests := []tc{
		{
			name: "simple present",
			build: func(h *map[string][]string) {
				(*h)["X-Request-ID"] = []string{"abc-123"}
			},
			param: ParamConfig{
				Source: ParamSourceHeader,
				Name:   "X-Request-ID",
			},
			want: "abc-123",
		},
		{
			name: "case-insensitive header name",
			build: func(h *map[string][]string) {
				(*h)["x-request-id"] = []string{"lower-ok"}
			},
			param: ParamConfig{
				Source: ParamSourceHeader,
				Name:   "X-Request-ID",
			},
			want: "lower-ok",
		},
		{
			name:  "missing -> error",
			build: func(h *map[string][]string) {},
			param: ParamConfig{
				Source: ParamSourceHeader,
				Name:   "X-Api-Key",
			},
			wantErr: "value missing X-Api-Key",
		},
		{
			name: "empty value uses Default",
			build: func(h *map[string][]string) {
				(*h)["X-Role"] = []string{""}
			},
			param: ParamConfig{
				Source:  ParamSourceHeader,
				Name:    "X-Role",
				Default: "guest",
			},
			want: "guest",
		},
		{
			name: "empty without default -> error",
			build: func(h *map[string][]string) {
				(*h)["X-Token"] = []string{""}
			},
			param: ParamConfig{
				Source: ParamSourceHeader,
				Name:   "X-Token",
			},
			wantErr: "value missing X-Token",
		},
		{
			name: "multiple values -> first one is used",
			build: func(h *map[string][]string) {
				(*h)["X-Env"] = []string{"prod", "staging"}
			},
			param: ParamConfig{
				Source: ParamSourceHeader,
				Name:   "X-Env",
			},
			want: "prod",
		},
		{
			name: "Expr overrides Name",
			build: func(h *map[string][]string) {
				(*h)["X-Project-ID"] = []string{"p-001"}
			},
			param: ParamConfig{
				Source: ParamSourceHeader,
				Name:   "Ignored-Name",
				Expr:   "X-Project-ID", // assumes ParamConfig.Key() prefers Expr
			},
			want: "p-001",
		},
		{
			name: "header with dashes and dots literal",
			build: func(h *map[string][]string) {
				(*h)["X-User.Name"] = []string{"mike"}
			},
			param: ParamConfig{
				Source: ParamSourceHeader,
				Name:   "X-User.Name",
			},
			want: "mike",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithHeaders(t, tt.build)
			got, err := getValue(c, tt.param)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetValue_BasicAuthUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type tc struct {
		name    string
		user    string
		pass    string
		with    bool
		param   ParamConfig
		want    string
		wantErr string
	}

	tests := []tc{
		{
			name: "valid basic auth user extracted",
			user: "michal",
			pass: "secret",
			with: true,
			param: ParamConfig{
				Source: ParamSourceBasicAuthUser,
				Name:   "username",
			},
			want: "michal",
		},
		{
			name: "missing auth -> error",
			with: false,
			param: ParamConfig{
				Source: ParamSourceBasicAuthUser,
				Name:   "username",
			},
			wantErr: "value missing username",
		},
		{
			name: "empty username with default fallback",
			user: "",
			pass: "nopass",
			with: true,
			param: ParamConfig{
				Source:  ParamSourceBasicAuthUser,
				Name:    "username",
				Default: "guest",
			},
			want: "guest",
		},
		{
			name: "empty username without default -> error",
			user: "",
			pass: "nopass",
			with: true,
			param: ParamConfig{
				Source: ParamSourceBasicAuthUser,
				Name:   "username",
			},
			wantErr: "value missing username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithBasicAuth(t, tt.user, tt.pass, tt.with)
			got, err := getValue(c, tt.param)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetValue_HTTPMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type tc struct {
		name    string
		method  string
		rawURL  string
		param   ParamConfig
		want    string
		wantErr bool
	}

	tests := []tc{
		{
			name:   "returns GET",
			method: http.MethodGet,
			rawURL: "https://example.com/api/v1/resources",
			param: ParamConfig{
				Source: ParamSourceHTTPMethod,
				Name:   "httpMethod",
			},
			want: http.MethodGet,
		},
		{
			name:   "returns POST",
			method: http.MethodPost,
			rawURL: "https://example.com/api/v1/resources",
			param: ParamConfig{
				Source: ParamSourceHTTPMethod,
				Name:   "httpMethod",
			},
			want: http.MethodPost,
		},
		{
			name:   "returns PUT",
			method: http.MethodPut,
			rawURL: "https://example.com/api/v1/resources/abc",
			param: ParamConfig{
				Source: ParamSourceHTTPMethod,
				Name:   "httpMethod",
			},
			want: http.MethodPut,
		},
		{
			name:   "returns DELETE",
			method: http.MethodDelete,
			rawURL: "https://example.com/api/v1/resources/123",
			param: ParamConfig{
				Source: ParamSourceHTTPMethod,
				Name:   "httpMethod",
			},
			want: http.MethodDelete,
		},
		{
			name:   "no default used for non-empty method",
			method: http.MethodPatch,
			rawURL: "https://example.com/api/v1/resources/123",
			param: ParamConfig{
				Source:  ParamSourceHTTPMethod,
				Name:    "httpMethod",
				Default: "SHOULD_NOT_USE",
			},
			want: http.MethodPatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithURL(t, tt.method, tt.rawURL)
			got, err := getValue(c, tt.param)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetValue_UnknownSource(t *testing.T) {
	gin.SetMode(gin.TestMode)

	param := ParamConfig{
		Source: "not_a_real_source",
		Name:   "foo",
	}

	c := ctxEmpty(t)
	got, err := getValue(c, param)

	require.Error(t, err)
	assert.Empty(t, got)
	assert.Equal(t, "unknown source for not_a_real_source", err.Error())
}

func TestClaimsJSONFromAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	claims := `{"sub":"123","name":"Alice"}`
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(claims))
	validJWT := "hdr." + payloadB64 + ".sig"

	tests := []struct {
		name    string
		auth    string
		want    string
		wantErr string
	}{
		{
			name: "ok - proper Bearer with valid JWT",
			auth: "Bearer " + validJWT,
			want: claims,
		},
		{
			name: "ok - case-insensitive bearer",
			auth: "bEaReR " + validJWT,
			want: claims,
		},
		{
			name:    "error - missing header",
			auth:    "",
			wantErr: "missing or non-bearer",
		},
		{
			name:    "error - non-bearer scheme",
			auth:    "Basic abc",
			wantErr: "missing or non-bearer",
		},
		{
			name:    "error - 'Bearer' without space or token",
			auth:    "Bearer",
			wantErr: "missing or non-bearer",
		},
		{
			name:    "error - 'Bearer ' but no token",
			auth:    "Bearer ",
			wantErr: "invalid JWT format",
		},
		{
			name:    "error - token without dot",
			auth:    "Bearer notajwt",
			wantErr: "invalid JWT format",
		},
		{
			name:    "error - payload not base64url",
			auth:    "Bearer hdr.not_base64!.sig",
			wantErr: "illegal",
		},
		{
			name: "ok - two parts only (header.payload)",
			auth: "Bearer hdr." + payloadB64,
			want: claims,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := ctxWithAuth(t, tc.auth)
			got, err := claimsJSONFromAuthHeader(c)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantErr))
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}
}

func TestGetValue_Claims(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const claimsJSON = `{
	  "sub": "9e4fdb1c-3345-4c07-98d9-73b993c9dd42",
	  "aud": ["acme", "api"],
	  "acme/serviceaccount/token.source": "oauth2",
	  "acme/serviceaccount/namespace": "api",
	  "acme/project/project.id": "2dec85bc-7cd7-4b76-9e7b-e47d844a61d8",
	  "azp": "michal-test-aoeyd81@sa.acme.cloud",
	  "iss": "acme/serviceaccount",
	  "acme/serviceaccount/service-account.uid": "9e4fdb1c-3345-4c07-98d9-73b993c9dd42",
	  "exp": 1758732816,
	  "iat": 1758729216,
	  "email": "michal-test-aoeyd81@sa.acme.cloud",
	  "jti": "a03923c1-5e99-488a-bd1a-e201af956d17"
	}`
	jwt := jwtWithClaims(claimsJSON)

	type tc struct {
		name    string
		auth    string
		param   ParamConfig
		want    string
		wantErr string
	}

	tests := []tc{
		{
			name: "sub",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "sub",
			},
			want: "9e4fdb1c-3345-4c07-98d9-73b993c9dd42",
		},
		{
			name: "iss",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "iss",
			},
			want: "acme/serviceaccount",
		},
		{
			name: "email",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "email",
			},
			want: "michal-test-aoeyd81@sa.acme.cloud",
		},
		{
			name: "namespace slash key",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "acme/serviceaccount/namespace",
			},
			want: "api",
		},
		{
			name: "aud[0] via path",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "aud.0",
			},
			want: "acme",
		},
		{
			name: "exp numeric -> string",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "exp",
			},
			want: "1758732816",
		},
		{
			name: "project.id via escaped dot",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Expr:   "acme/project/project\\.id", // gjson escape for literal dot
				Name:   "project.id",
			},
			want: "2dec85bc-7cd7-4b76-9e7b-e47d844a61d8",
		},
		{
			name: "empty value uses Default",
			auth: "Bearer " + jwtWithClaims(`{"role":""}`),
			param: ParamConfig{
				Source:  ParamSourceClaim,
				Name:    "role",
				Default: "guest",
			},
			want: "guest",
		},
		{
			name: "missing Authorization header",
			auth: "",
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "sub",
			},
			wantErr: "invalid or missing Bearer Authorization header",
		},
		{
			name: "non-bearer scheme",
			auth: "Basic abc",
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "sub",
			},
			wantErr: "invalid or missing Bearer Authorization header",
		},
		{
			name: "invalid JWT format",
			auth: "Bearer notajwt",
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "sub",
			},
			wantErr: "invalid or missing Bearer Authorization header",
		},
		{
			name: "invalid base64 payload",
			auth: "Bearer hdr.not_base64!.sig",
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "sub",
			},
			wantErr: "invalid or missing Bearer Authorization header",
		},
		{
			name: "missing claim (simple)",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "does_not_exist",
			},
			wantErr: "missing claim does_not_exist",
		},
		{
			name: "missing claim (escaped dot expr)",
			auth: "Bearer " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Expr:   "foo/bar/baz\\.id",
				Name:   "baz.id",
			},
			wantErr: "missing claim foo/bar/baz\\.id",
		},
		{
			name: "empty value without default -> value missing <Name>",
			auth: "Bearer " + jwtWithClaims(`{"emptyField":""}`),
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "emptyField",
			},
			wantErr: "value missing emptyField",
		},
		{
			name: "case-insensitive bearer accepted",
			auth: "bEaReR " + jwt,
			param: ParamConfig{
				Source: ParamSourceClaim,
				Name:   "iss",
			},
			want: "acme/serviceaccount",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithAuth(t, tt.auth)
			got, err := getValue(c, tt.param)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildRuleValue_NoCases(t *testing.T) {
	paramValues := map[string]string{
		"projectId": "p123",
		"topicId":   "t99",
	}

	tests := []struct {
		name    string
		rule    RuleConfig
		want    string
		wantErr string
	}{
		{
			name: "ok with explicit format and params",
			rule: RuleConfig{
				Format:     "pubsub:eu-central-1:%s:topics/%s",
				ParamNames: []string{"projectId", "topicId"},
			},
			want: "pubsub:eu-central-1:p123:topics/t99",
		},
		{
			name: "default format with single arg",
			rule: RuleConfig{
				Format:     "", // default to "%s"
				ParamNames: []string{"topicId"},
			},
			want: "t99",
		},
		{
			name: "missing param error",
			rule: RuleConfig{
				Format:     "x:%s:%s",
				ParamNames: []string{"projectId", "missingKey"},
			},
			wantErr: `missing param "missingKey"`,
		},
		{
			name: "missing format with >1 args error",
			rule: RuleConfig{
				Format:     "",
				ParamNames: []string{"projectId", "topicId"},
			},
			wantErr: "missing rule format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRuleValue(tt.rule, paramValues)
			if tt.wantErr != "" {
				require.Error(t, err)
				if tt.wantErr != "" {
					assert.Contains(t, err.Error(), tt.wantErr)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildRuleValue_Cases(t *testing.T) {
	params := map[string]string{
		"projectId": "p1",
		"sub":       "sa/abc",
		"topicId":   "topA",
	}

	t.Run("first matching case wins", func(t *testing.T) {
		rule := RuleConfig{
			Cases: []RuleCase{
				{
					When:       `hasPrefix(sub, "user/")`, // false
					Format:     "iam::%s:my-user/%s",
					ParamNames: []string{"projectId", "sub"},
				},
				{
					When:       `hasPrefix(sub, "sa/")`, // true
					Format:     "iam::%s:my-sa/%s",
					ParamNames: []string{"projectId", "sub"},
				},
				{
					// would also match, but should not be reached
					When:       `hasPrefix(sub, "sa/")`,
					Format:     "OVERRIDDEN:%s:%s",
					ParamNames: []string{"projectId", "sub"},
				},
			},
		}

		got, err := buildRuleValue(rule, params)
		require.NoError(t, err)
		assert.Equal(t, "iam::p1:my-sa/sa/abc", got)
	})

	t.Run("no case matched -> error", func(t *testing.T) {
		rule := RuleConfig{
			Cases: []RuleCase{
				{
					When:       `hasPrefix(sub, "user/")`, // false
					Format:     "x:%s",
					ParamNames: []string{"sub"},
				},
				{
					When:       `equalsIgnoreCase(topicId, "other")`, // false
					Format:     "y:%s",
					ParamNames: []string{"topicId"},
				},
			},
		}
		_, err := buildRuleValue(rule, params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no case matched")
	})

	t.Run("invalid when expression bubbles up", func(t *testing.T) {
		rule := RuleConfig{
			Cases: []RuleCase{
				{
					When:       `hasPrefix(sub)`, // invalid: missing arg
					Format:     "x:%s",
					ParamNames: []string{"sub"},
				},
			},
		}
		_, err := buildRuleValue(rule, params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "when")
	})
}

func ctxWithHeaders(t *testing.T, set func(hdr *map[string][]string)) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	if set != nil {
		// Allow caller to set multiple or repeated headers.
		m := map[string][]string{}
		set(&m)
		for k, vs := range m {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	c.Request = req
	return c
}

func ctxWithBasicAuth(t *testing.T, username, password string, withAuth bool) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	if withAuth {
		req.SetBasicAuth(username, password)
	}
	c.Request = req
	return c
}

func ctxWithPathParam(t *testing.T, key, val string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/whatever", nil)
	if key != "" {
		c.Params = gin.Params{gin.Param{Key: key, Value: val}}
	}
	return c
}
func ctxWithQuery(t *testing.T, rawQuery string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/whatever?"+rawQuery, nil)
	c.Request = req
	return c
}

func ctxWithAuth(t *testing.T, auth string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	c.Request = req
	return c
}

func ctxEmpty(t *testing.T) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/whatever", nil)
	return c
}

func ctxWithURL(t *testing.T, method, rawURL string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, rawURL, nil)
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c
}

// builds a minimal JWT with the given claims JSON as payload
func jwtWithClaims(claimsJSON string) string {
	hdr := "eyJhbGciOiJub25lIn0" // {"alg":"none"} base64url; exact value doesn't matter
	payload := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return hdr + "." + payload + ".sig"
}
