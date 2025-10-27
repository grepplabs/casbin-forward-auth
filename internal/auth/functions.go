package auth

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var (
	regexCache sync.Map // map[string]*regexp.Regexp
)

type BuiltinFunc func(string, ParamConfig) (string, error)

var builtinFunc = map[string]BuiltinFunc{
	"b64dec": func(s string, _ ParamConfig) (string, error) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("invalid base64: %w", err)
		}
		return string(b), nil
	},
	"firstlabel": func(s string, _ ParamConfig) (string, error) {
		if s == "" {
			return "", nil
		}
		return strings.SplitN(s, ".", 2)[0], nil
	},
	"regex": func(s string, p ParamConfig) (string, error) {
		if strings.TrimSpace(p.Expr) == "" {
			return "", fmt.Errorf("regex pattern (Expr) is empty for %s", p.Name)
		}
		re, err := getCachedRegex(p.Expr)
		if err != nil {
			return "", fmt.Errorf("invalid regex %q: %w", p.Expr, err)
		}
		m := re.FindStringSubmatch(s)
		if len(m) < 2 {
			return "", fmt.Errorf("no match for %q in %q", p.Expr, s)
		}
		// the first capture group (the part in parentheses (...))
		return m[1], nil
	},
	"tolower": func(s string, _ ParamConfig) (string, error) {
		return strings.ToLower(s), nil
	},
	"toupper": func(s string, _ ParamConfig) (string, error) {
		return strings.ToUpper(s), nil
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
	return fn(val, p)
}

func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re, nil
		}
		return nil, fmt.Errorf("unexpected type in cache for %q: %T", pattern, v)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}
