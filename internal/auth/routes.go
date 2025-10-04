package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/grepplabs/loggo/zlog"
	"github.com/tidwall/gjson"
)

const ctxKeyJWTClaims = "jwt_claims"

// get or parse once and store claims JSON for this request
func claimsJSONFromContext(c *gin.Context) ([]byte, error) {
	if v, ok := c.Get(ctxKeyJWTClaims); ok {
		return v.([]byte), nil
	}
	claimsJSON, err := claimsJSONFromAuthHeader(c)
	if err != nil {
		return nil, err
	}
	c.Set(ctxKeyJWTClaims, claimsJSON)
	return claimsJSON, nil
}

func claimsJSONFromAuthHeader(c *gin.Context) ([]byte, error) {
	tokenHeader := c.GetHeader("Authorization")
	if len(tokenHeader) < 7 || !strings.EqualFold(tokenHeader[:7], "bearer ") {
		return nil, fmt.Errorf("missing or non-bearer Authorization header")
	}
	tok := tokenHeader[7:]
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

func makeHandler(route Route, enforcer *casbin.SyncedEnforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		paramValues := make(map[string]string)
		for _, p := range route.Params {
			// extract value
			val, err := getValue(c, p)
			if err != nil {
				c.String(http.StatusBadRequest, fmt.Sprintf("failded to get value: %s", err))
				return
			}
			// transform - apply function
			val, err = applyFunction(val, p)
			if err != nil {
				c.String(http.StatusBadRequest, fmt.Sprintf("failded to apply function value: %s", err))
				return
			}
			paramValues[p.Name] = val
		}

		// build rules
		rules := make([]any, len(route.Rules))
		for i, r := range route.Rules {
			rule, err := buildRuleValue(r, paramValues)
			if err != nil {
				c.String(http.StatusBadRequest, fmt.Sprintf("rule %d build failed: %v", i, err))
				return
			}
			rules[i] = rule
		}

		// enforce
		zlog.Infof("Enforcing %v", rules)

		ok, reason, err := enforcer.EnforceEx(rules...)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("enforce error: %s", err))
			return
		}
		if ok {
			zlog.Infof("authorized reason: %v", reason)
			c.String(http.StatusOK, fmt.Sprintf("authorized %v", reason))
			return
		}
		c.String(http.StatusForbidden, "rejected")
	}
}

func getValue(c *gin.Context, p ParamConfig) (string, error) {
	var val string

	switch p.Source {
	case ParamSourcePath:
		val = c.Param(p.Key())
	case ParamSourceQuery:
		val = c.Query(p.Key())
	case ParamSourceHeader:
		val = c.GetHeader(p.Key())
	case ParamSourceClaim:
		claimsJSON, err := claimsJSONFromContext(c)
		if err != nil {
			return "", fmt.Errorf("invalid or missing Bearer Authorization header")
		}
		//TODO: could use other function to build concat principal
		//TODO: can also provide a context for a string format
		res := gjson.ParseBytes(claimsJSON).Get(p.Key())
		if !res.Exists() {
			return "", fmt.Errorf("missing claim %s", p.Key())
		}
		val = res.String()
	case ParamSourceBasicAuthUser:
		user, _, ok := c.Request.BasicAuth()
		if ok {
			val = user
		}
	default:
		return "", fmt.Errorf("unknown source for %s", p.Source)
	}
	// validate value
	if len(val) == 0 {
		if len(p.Default) == 0 {
			return "", fmt.Errorf("value missing %s", p.Name)
		}
		val = p.Default
	}
	return val, nil
}

func buildRuleValue(rule RuleConfig, paramValues map[string]string) (string, error) {
	if len(rule.Cases) > 0 {
		for _, cs := range rule.Cases {
			ok, err := evalWhen(cs.When, paramValues)
			if err != nil {
				return "", fmt.Errorf("rule case when failed: %w", err)
			}
			if !ok {
				continue
			}
			// matched case
			return formatRule(cs.Format, cs.ParamNames, paramValues)
		}
		return "", fmt.Errorf("no case matched")
	}
	return formatRule(rule.Format, rule.ParamNames, paramValues)
}

func SetupRoutes(r *gin.Engine, routes []Route, enforcer *casbin.SyncedEnforcer) *gin.Engine {
	if len(routes) == 0 {
		zlog.Infof("no auth routes defined")
	}

	for _, route := range routes {
		handler := makeHandler(route, enforcer)
		method := strings.ToUpper(route.HttpMethod)

		for _, relativePath := range route.RelativePaths {
			zlog.Infof("add auth route %s %s", method, relativePath)
			if method == HttpMethodAny {
				r.Any(relativePath, handler)
			} else {
				r.Handle(route.HttpMethod, relativePath, handler)
			}
		}
	}
	return r
}
