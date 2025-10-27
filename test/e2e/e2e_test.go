package e2e

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	httphelper "github.com/gruntwork-io/terratest/modules/http-helper"
	"github.com/gruntwork-io/terratest/modules/k8s"
	terratesting "github.com/gruntwork-io/terratest/modules/testing"
	"github.com/stretchr/testify/require"
)

const (
	configPath = "../../kubeconfig-casbin-traefik"
	baseURL    = "http://localhost:30080"
)

func newKubectlOptions() *k8s.KubectlOptions {
	return k8s.NewKubectlOptions("", configPath, "")
}

func kubectlDeleteIgnoreNotFound(t terratesting.TestingT, options *k8s.KubectlOptions, configPath string) {
	require.NoError(t, k8s.RunKubectlE(t, options, "delete", "--ignore-not-found=true", "-f", configPath))
}

func buildURL(path string) string {
	return baseURL + path
}

func requireRejected(t *testing.T, method string, url string, headers map[string]string) {
	const expectedBody = `{"error":"rejected"}`
	httphelper.HTTPDoWithValidationRetry(t, method, url, nil, headers, http.StatusForbidden, expectedBody, 10, 2*time.Second, nil)
}

func requireNotFound(t *testing.T, method string, url string, headers map[string]string) {
	const expectedBody = `{"error":"404 page not found"}`
	httphelper.HTTPDoWithValidationRetry(t, method, url, nil, headers, http.StatusForbidden, expectedBody, 10, 2*time.Second, nil)
}

func requireOK(t *testing.T, method string, url string, headers map[string]string) {
	httphelper.HTTPDoWithRetry(t, method, url, nil, headers, http.StatusOK, 5, 2*time.Second, nil)
}

func newTestBearerToken(t *testing.T) string {
	t.Helper()

	claims := jwt.MapClaims{
		"acme/project/project.id": "123456789012",
		"aud":                     []string{"acme", "api"},
		"azp":                     "michal-test-aoeyd81@sa.acme.cloud",
		"email":                   "michal-test-aoeyd81@sa.acme.cloud",
		"exp":                     1760033573,
		"iat":                     1760029973,
		"iss":                     "acme/serviceaccount",
		"jti":                     "a03923c1-5e99-488a-bd1a-e201af956d17",
		"sub":                     "9e4fdb1c-3345-4c07-98d9-73b993c9dd42",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	token, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	return token
}

func newTestBasic(t *testing.T, username string) string {
	t.Helper()
	auth := fmt.Sprintf("%s:%s", username, "pass")
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
