package auth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

var (
	whenProgCache sync.Map // map[string]*vm.vm

	baseWhenEnv = map[string]any{
		"hasPrefix":        fnHasPrefix,
		"hasSuffix":        fnHasSuffix,
		"contains":         fnContains,
		"equalsIgnoreCase": fnEqualsIgnoreCase,
		"equals":           fnEquals,
		"match":            fnMatch,
	}
)

func formatRule(format string, names []string, paramValues map[string]string) (string, error) {
	args := make([]any, len(names))
	for i, name := range names {
		val, ok := paramValues[name]
		if !ok {
			return "", fmt.Errorf("missing param %q", name)
		}
		args[i] = val
	}
	// default format if 1 arg and empty format
	if format == "" {
		if len(args) == 1 {
			format = "%s"
		} else {
			return "", errors.New("missing rule format")
		}
	}
	return fmt.Sprintf(format, args...), nil
}

func compileWhen(exprText string) (*vm.Program, error) {
	if v, ok := whenProgCache.Load(exprText); ok {
		if prog, ok := v.(*vm.Program); ok {
			return prog, nil
		}
		return nil, fmt.Errorf("unexpected type in cache for %q: %T", exprText, v)
	}
	prog, err := expr.Compile(
		exprText,
		expr.Env(map[string]any{}),
		expr.AsBool(), // ensure the expression returns bool
		expr.Optimize(true),
		expr.AllowUndefinedVariables(),
	)
	if err != nil {
		return nil, err
	}
	whenProgCache.Store(exprText, prog)
	return prog, nil
}

func makeWhenEnv(params map[string]string) map[string]any {
	env := make(map[string]any, len(baseWhenEnv)+1+len(params))
	for k, v := range baseWhenEnv {
		env[k] = v
	}
	env["p"] = params
	// also expose each key directly (sub, projectId, ...)
	for k, v := range params {
		env[k] = v
	}
	return env
}

func evalWhen(when string, params map[string]string) (bool, error) {
	// fast-path
	switch when {
	case "":
		return false, errors.New("missing when")
	case "true":
		return true, nil
	case "false":
		return false, nil
	}

	prog, err := compileWhen(when)
	if err != nil {
		return false, fmt.Errorf("invalid when expression %q: %w", when, err)
	}

	out, err := expr.Run(prog, makeWhenEnv(params))
	if err != nil {
		return false, err
	}

	b, ok := out.(bool)
	if !ok {
		return false, errors.New("when expression did not return bool")
	}
	return b, nil
}

var fnHasPrefix = func(params ...any) (any, error) {
	s, prefix, err := twoStrings("hasPrefix", "(s, prefix)", params...)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(s, prefix), nil
}

var fnHasSuffix = func(params ...any) (any, error) {
	s, suffix, err := twoStrings("hasSuffix", "(s, suffix)", params...)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(s, suffix), nil
}

var fnContains = func(params ...any) (any, error) {
	s, sub, err := twoStrings("contains", "(s, sub)", params...)
	if err != nil {
		return false, err
	}
	return strings.Contains(s, sub), nil
}

var fnEqualsIgnoreCase = func(params ...any) (any, error) {
	a, b, err := twoStrings("equalsIgnoreCase", "(a, b)", params...)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(a, b), nil
}

var fnEquals = func(params ...any) (any, error) {
	a, b, err := twoStrings("equals", "(a, b)", params...)
	if err != nil {
		return false, err
	}
	return a == b, nil
}

var fnMatch = func(params ...any) (any, error) {
	s, re, err := twoStrings("match", "(s, re)", params...)
	if err != nil {
		return false, err
	}
	ok, e := regexp.MatchString(re, s)
	if e != nil {
		return false, e
	}
	return ok, nil
}

// twoStrings: enforce 2 args and both strings
func twoStrings(fname, sig string, params ...any) (string, string, error) {
	if len(params) != 2 {
		return "", "", fmt.Errorf("%s %s expects 2 args", fname, sig)
	}
	a, ok1 := params[0].(string)
	b, ok2 := params[1].(string)
	if !ok1 || !ok2 {
		return "", "", fmt.Errorf("%s %s expects string args", fname, sig)
	}
	return a, b, nil
}
