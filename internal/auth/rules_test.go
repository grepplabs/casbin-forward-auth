package auth

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvalWhen_FastPaths(t *testing.T) {
	_, err := evalWhen("", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing when")

	b, err := evalWhen("true", nil)
	require.NoError(t, err)
	assert.True(t, b)

	b, err = evalWhen("false", nil)
	require.NoError(t, err)
	assert.False(t, b)
}

func TestCompileWhen_UsesCache(t *testing.T) {
	whenProgCache = sync.Map{}

	exprText := `hasPrefix(sub, "abc")`

	p1, err := compileWhen(exprText)
	require.NoError(t, err, "first compile should succeed")

	p2, err := compileWhen(exprText)
	require.NoError(t, err, "second compile should also succeed")

	assert.Same(t, p1, p2, "expected cached program pointer to be identical")
}

func TestFnHasPrefix(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		want    bool
		wantErr string
	}{
		{
			name: "prefix matches",
			args: []any{"abcdef", "abc"},
			want: true,
		},
		{
			name: "prefix does not match",
			args: []any{"abcdef", "abd"},
			want: false,
		},
		{
			name:    "not enough args",
			args:    []any{"only-one"},
			wantErr: "expects 2 args",
		},
		{
			name:    "too many args",
			args:    []any{"a", "b", "c"},
			wantErr: "expects 2 args",
		},
		{
			name:    "first arg not a string",
			args:    []any{123, "a"},
			wantErr: "expects string args",
		},
		{
			name:    "second arg not a string",
			args:    []any{"abc", 456},
			wantErr: "expects string args",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnHasPrefix(tt.args...)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			b, ok := got.(bool)
			require.True(t, ok, "expected bool result")
			assert.Equal(t, tt.want, b)
		})
	}
}

func TestFnHasSuffix(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		want    bool
		wantErr string
	}{
		{
			name: "suffix matches",
			args: []any{"abcdef", "def"},
			want: true,
		},
		{
			name: "suffix does not match",
			args: []any{"abcdef", "deg"},
			want: false,
		},
		{
			name:    "not enough args",
			args:    []any{"only-one"},
			wantErr: "expects 2 args",
		},
		{
			name:    "too many args",
			args:    []any{"a", "b", "c"},
			wantErr: "expects 2 args",
		},
		{
			name:    "first arg not a string",
			args:    []any{123, "a"},
			wantErr: "expects string args",
		},
		{
			name:    "second arg not a string",
			args:    []any{"abc", 456},
			wantErr: "expects string args",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnHasSuffix(tt.args...)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			b, ok := got.(bool)
			require.True(t, ok, "expected bool result")
			assert.Equal(t, tt.want, b)
		})
	}
}

func TestFnContains(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		want    bool
		wantErr string
	}{
		{
			name: "substring exists",
			args: []any{"hello world", "world"},
			want: true,
		},
		{
			name: "substring does not exist",
			args: []any{"hello world", "mars"},
			want: false,
		},
		{
			name:    "not enough args",
			args:    []any{"only-one"},
			wantErr: "expects 2 args",
		},
		{
			name:    "too many args",
			args:    []any{"a", "b", "c"},
			wantErr: "expects 2 args",
		},
		{
			name:    "first arg not a string",
			args:    []any{123, "a"},
			wantErr: "expects string args",
		},
		{
			name:    "second arg not a string",
			args:    []any{"abc", 456},
			wantErr: "expects string args",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnContains(tt.args...)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			b, ok := got.(bool)
			require.True(t, ok, "expected bool result")
			assert.Equal(t, tt.want, b)
		})
	}
}

func TestFnEqualsIgnoreCase(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		want    bool
		wantErr string
	}{
		{
			name: "strings equal ignoring case",
			args: []any{"Hello", "hello"},
			want: true,
		},
		{
			name: "strings equal with same case",
			args: []any{"GoLang", "GoLang"},
			want: true,
		},
		{
			name: "strings not equal",
			args: []any{"abc", "xyz"},
			want: false,
		},
		{
			name:    "not enough args",
			args:    []any{"only-one"},
			wantErr: "expects 2 args",
		},
		{
			name:    "too many args",
			args:    []any{"a", "b", "c"},
			wantErr: "expects 2 args",
		},
		{
			name:    "first arg not a string",
			args:    []any{123, "a"},
			wantErr: "expects string args",
		},
		{
			name:    "second arg not a string",
			args:    []any{"abc", 456},
			wantErr: "expects string args",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnEqualsIgnoreCase(tt.args...)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			b, ok := got.(bool)
			require.True(t, ok, "expected bool result")
			assert.Equal(t, tt.want, b)
		})
	}
}

func TestFnEquals(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		want    bool
		wantErr string
	}{
		{
			name: "strings exactly equal",
			args: []any{"hello", "hello"},
			want: true,
		},
		{
			name: "strings differ in case",
			args: []any{"Hello", "hello"},
			want: false,
		},
		{
			name: "strings completely different",
			args: []any{"abc", "xyz"},
			want: false,
		},
		{
			name:    "not enough args",
			args:    []any{"only-one"},
			wantErr: "expects 2 args",
		},
		{
			name:    "too many args",
			args:    []any{"a", "b", "c"},
			wantErr: "expects 2 args",
		},
		{
			name:    "first arg not a string",
			args:    []any{123, "a"},
			wantErr: "expects string args",
		},
		{
			name:    "second arg not a string",
			args:    []any{"abc", 456},
			wantErr: "expects string args",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnEquals(tt.args...)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			b, ok := got.(bool)
			require.True(t, ok, "expected bool result")
			assert.Equal(t, tt.want, b)
		})
	}
}

func TestFnMatch(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		want    bool
		wantErr string
	}{
		{
			name: "regex matches",
			args: []any{"hello123", `^hello\d+$`},
			want: true,
		},
		{
			name: "regex does not match",
			args: []any{"hello", `^\d+$`},
			want: false,
		},
		{
			name:    "invalid regex pattern",
			args:    []any{"hello", "("},
			wantErr: "error parsing regexp",
		},
		{
			name:    "not enough args",
			args:    []any{"only-one"},
			wantErr: "expects 2 args",
		},
		{
			name:    "too many args",
			args:    []any{"a", "b", "c"},
			wantErr: "expects 2 args",
		},
		{
			name:    "first arg not a string",
			args:    []any{123, `^\d+$`},
			wantErr: "expects string args",
		},
		{
			name:    "second arg not a string",
			args:    []any{"abc", 456},
			wantErr: "expects string args",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnMatch(tt.args...)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			b, ok := got.(bool)
			require.True(t, ok, "expected bool result")
			assert.Equal(t, tt.want, b)
		})
	}
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
