// nolint: funlen
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyFunction(t *testing.T) {
	pc := func(name, fn string) ParamConfig {
		return ParamConfig{
			Name:     name,
			Function: fn,
		}
	}

	tests := []struct {
		name    string
		val     string
		p       ParamConfig
		want    string
		wantErr string
	}{
		{
			name: "no function returns original value",
			val:  "hello",
			p:    pc("any", ""),
			want: "hello",
		},
		{
			name:    "function specified but empty input -> error mentions param name",
			val:     "",
			p:       pc("myParam", "b64dec"),
			wantErr: "function value missing myParam",
		},
		{
			name:    "unknown function -> clear error",
			val:     "abc",
			p:       pc("x", "notAFunction"),
			wantErr: `unknown function "notAFunction"`,
		},
		{
			name: "b64dec happy path",
			val:  "aGVsbG8=", // "hello"
			p:    pc("x", "b64dec"),
			want: "hello",
		},
		{
			name:    "b64dec invalid base64",
			val:     "!!not-base64!!",
			p:       pc("x", "b64dec"),
			wantErr: "invalid base64",
		},
		{
			name: "firstlabel multi-label DNS name",
			val:  "prefix.namespace.svc.cluster.local",
			p:    pc("x", "firstlabel"),
			want: "prefix",
		},
		{
			name: "firstlabel single label",
			val:  "justone",
			p:    pc("x", "firstlabel"),
			want: "justone",
		},
		{
			name: "firstlabel fqdn with trailing dot",
			val:  "example.com.",
			p:    pc("x", "firstlabel"),
			want: "example",
		},
		{
			name: "firstlabel leading dot (empty first label)",
			val:  ".hidden.internal",
			p:    pc("x", "firstlabel"),
			want: "",
		},
		{
			name: "function name is case-insensitive",
			val:  "aGVsbG8=",
			p:    pc("x", "B64DEC"),
			want: "hello",
		},
		{
			name:    "firstlabel with empty value still errors at applyFunction",
			val:     "",
			p:       pc("host", "firstlabel"),
			wantErr: "function value missing host",
		},
		{
			name: "regex happy path - first label from host",
			val:  "eu1.pubsub.acme.cloud",
			p: ParamConfig{
				Name:     "topicId",
				Function: "regex",
				Expr:     `^([^.]+)\.`, // capture everything before first dot
			},
			want: "eu1",
		},
		{
			name: "regex happy path - projectId from URL path",
			val:  "/v1/projects/acme-123/topics/payments",
			p: ParamConfig{
				Name:     "projectId",
				Function: "regex",
				Expr:     `^/v1/projects/([^/]+)/topics/[^/]+$`,
			},
			want: "acme-123",
		},
		{
			name: "regex no match -> clear error",
			val:  "/v1/users/alice",
			p: ParamConfig{
				Name:     "projectId",
				Function: "regex",
				Expr:     `^/v1/projects/([^/]+)/topics/[^/]+$`,
			},
			wantErr: "no match",
		},
		{
			name: "regex invalid pattern -> clear error",
			val:  "anything",
			p: ParamConfig{
				Name:     "x",
				Function: "regex",
				Expr:     `([unclosed`, // invalid
			},
			wantErr: "invalid regex",
		},
		{
			name: "regex pattern without capture group -> treated as no match",
			val:  "/v1/projects/acme/topics/x",
			p: ParamConfig{
				Name:     "x",
				Function: "regex",
				Expr:     `^/v1/projects/.+/topics/.+$`, // no (...)
			},
			wantErr: "no match",
		},
		{
			name: "regex function name is case-insensitive",
			val:  "alice@example.com",
			p: ParamConfig{
				Name:     "user",
				Function: "ReGeX",
				Expr:     `^([^@]+)@`,
			},
			want: "alice",
		},
		{
			name: "regex empty pattern -> error",
			val:  "foo",
			p: ParamConfig{
				Name:     "x",
				Function: "regex",
				Expr:     "",
			},
			wantErr: "regex pattern (Expr) is empty",
		},
		{
			name: "regex empty pattern -> error",
			val:  "foo",
			p: ParamConfig{
				Name:     "x",
				Function: "regex",
				Expr:     "",
			},
			wantErr: "regex pattern (Expr) is empty",
		},
		{
			name: "tolower converts uppercase to lowercase",
			val:  "HeLLo WoRLD",
			p:    pc("x", "tolower"),
			want: "hello world",
		},
		{
			name: "toupper converts lowercase to uppercase",
			val:  "hello world",
			p:    pc("x", "toupper"),
			want: "HELLO WORLD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyFunction(tt.val, tt.p)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
