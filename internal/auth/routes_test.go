package auth

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimsJSONFromAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	claims := `{"sub":"123","name":"Alice"}`
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(claims))
	validJWT := "hdr." + payloadB64 + ".sig"

	tests := []struct {
		name        string
		auth        string
		want        string
		wantErrPart string
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
			name:        "error - missing header",
			auth:        "",
			wantErrPart: "missing or non-bearer",
		},
		{
			name:        "error - non-bearer scheme",
			auth:        "Basic abc",
			wantErrPart: "missing or non-bearer",
		},
		{
			name:        "error - 'Bearer' without space or token",
			auth:        "Bearer",
			wantErrPart: "missing or non-bearer",
		},
		{
			name:        "error - 'Bearer ' but no token",
			auth:        "Bearer ",
			wantErrPart: "invalid JWT format",
		},
		{
			name:        "error - token without dot",
			auth:        "Bearer notajwt",
			wantErrPart: "invalid JWT format",
		},
		{
			name:        "error - payload not base64url",
			auth:        "Bearer hdr.not_base64!.sig",
			wantErrPart: "illegal",
		},
		{
			name: "ok - two parts only (header.payload)",
			auth: "Bearer hdr." + payloadB64,
			want: claims,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := makeCtxWithAuth(t, tc.auth)
			got, err := claimsJSONFromAuthHeader(c)

			if tc.wantErrPart != "" {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantErrPart))
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
		tt := tt
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
		name      string
		rule      RuleConfig
		want      string
		wantErr   bool
		errSubstr string
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
			wantErr:   true,
			errSubstr: `missing param "missingKey"`,
		},
		{
			name: "missing format with >1 args error",
			rule: RuleConfig{
				Format:     "",
				ParamNames: []string{"projectId", "topicId"},
			},
			wantErr:   true,
			errSubstr: "missing rule format",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRuleValue(tt.rule, paramValues)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
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
					Format:     "iam:eu-central-1:%s:my-user/%s",
					ParamNames: []string{"projectId", "sub"},
				},
				{
					When:       `hasPrefix(sub, "sa/")`, // true
					Format:     "iam:eu-central-1:%s:my-sa/%s",
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
		assert.Equal(t, "iam:eu-central-1:p1:my-sa/sa/abc", got)
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
					When:       `equalFold(topicId, "other")`, // false
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

func TestFormatRule(t *testing.T) {
	params := map[string]string{
		"a": "A",
		"b": "B",
	}

	t.Run("ok", func(t *testing.T) {
		got, err := formatRule("x:%s-%s", []string{"a", "b"}, params)
		require.NoError(t, err)
		assert.Equal(t, "x:A-B", got)
	})

	t.Run("missing param", func(t *testing.T) {
		_, err := formatRule("x:%s", []string{"missing"}, params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `missing param "missing"`)
	})

	t.Run("default format with single arg", func(t *testing.T) {
		got, err := formatRule("", []string{"a"}, params)
		require.NoError(t, err)
		assert.Equal(t, "A", got)
	})

	t.Run("missing format with multiple args", func(t *testing.T) {
		_, err := formatRule("", []string{"a", "b"}, params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing rule format")
	})
}

func makeCtxWithAuth(t *testing.T, auth string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	c.Request = req
	return c
}

func ctxWithAuth(t *testing.T, auth string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	c.Request = req
	return c
}

// builds a minimal JWT with the given claims JSON as payload
func jwtWithClaims(claimsJSON string) string {
	hdr := "eyJhbGciOiJub25lIn0" // {"alg":"none"} base64url; exact value doesn't matter
	payload := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return hdr + "." + payload + ".sig"
}
