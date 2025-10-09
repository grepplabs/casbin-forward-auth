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
