package auth

import (
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
		"hasPrefix": fnHasPrefix,
		"hasSuffix": fnHasSuffix,
		"contains":  fnContains,
		"equalFold": fnEqualFold,
		"equal":     fnEqual,
		"match":     fnMatch,
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
			return "", fmt.Errorf("missing rule format")
		}
	}
	return fmt.Sprintf(format, args...), nil
}

func compileWhen(exprText string) (*vm.Program, error) {
	if prog, ok := whenProgCache.Load(exprText); ok {
		return prog.(*vm.Program), nil
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
		return false, fmt.Errorf("missing when")
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
		return false, fmt.Errorf("when expression did not return bool")
	}
	return b, nil
}

var fnHasPrefix = func(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("hasPrefix(s, prefix) expects 2 args")
	}
	s, _ := params[0].(string)
	prefix, _ := params[1].(string)
	return strings.HasPrefix(s, prefix), nil
}

var fnHasSuffix = func(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("hasSuffix(s, suffix) expects 2 args")
	}
	s, _ := params[0].(string)
	suffix, _ := params[1].(string)
	return strings.HasSuffix(s, suffix), nil
}

var fnContains = func(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("contains(s, sub) expects 2 args")
	}
	s, _ := params[0].(string)
	sub, _ := params[1].(string)
	return strings.Contains(s, sub), nil
}

var fnEqualFold = func(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("equalFold(a, b) expects 2 args")
	}
	a, _ := params[0].(string)
	b, _ := params[1].(string)
	return strings.EqualFold(a, b), nil
}

var fnEqual = func(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("equal(a, b) expects 2 args")
	}
	a, ok1 := params[0].(string)
	b, ok2 := params[1].(string)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("equal(a, b) expects string args")
	}
	return a == b, nil
}

var fnMatch = func(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("match(s, re) expects 2 args")
	}
	s, _ := params[0].(string)
	re, _ := params[1].(string)
	ok, err := regexp.MatchString(re, s)
	if err != nil {
		return false, err
	}
	return ok, nil
}
