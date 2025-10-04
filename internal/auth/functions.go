package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type BuiltinFunc func(string) (string, error)

var builtinFunc = map[string]BuiltinFunc{
	"b64dec": func(s string) (string, error) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("invalid base64: %w", err)
		}
		return string(b), nil
	},
	"firstlabel": func(s string) (string, error) {
		if s == "" {
			return "", nil
		}
		return strings.SplitN(s, ".", 2)[0], nil
	},
}

func applyFunction(val string, p ParamConfig) (string, error) {
	name := strings.TrimSpace(p.Function)
	if name == "" {
		return val, nil
	}
	if len(val) == 0 {
		return "", fmt.Errorf("function value missing %s", p.Name)
	}
	fn := builtinFunc[strings.ToLower(name)]
	if fn == nil {
		return "", fmt.Errorf("unknown function %q", name)
	}
	return fn(val)
}
