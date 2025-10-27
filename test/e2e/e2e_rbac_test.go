package e2e

import (
	"net/http"
	"testing"

	"github.com/gruntwork-io/terratest/modules/k8s"
)

func Test_RBAC_PubSub(t *testing.T) {
	options := newKubectlOptions()
	k8s.KubectlApply(t, options, "testdata/middleware-rbac.yml")

	kubeResourcePath := "testdata/rbac-echo-pubsub-policy.yaml"

	headers := map[string]string{
		"Host":          "orders.local",
		"Authorization": "Bearer " + newTestBearerToken(t),
	}
	publishURL := buildURL("/v1alpha/publish")
	pullURL := buildURL("/v1alpha/subscriptions/order-updates/pull")
	ackURL := buildURL("/v1alpha/subscriptions/order-updates/ack")
	nackURL := buildURL("/v1alpha/subscriptions/order-updates/nack")

	kubectlDeleteIgnoreNotFound(t, options, kubeResourcePath)

	requireRejected(t, http.MethodPost, publishURL, headers)
	requireRejected(t, http.MethodPost, pullURL, headers)
	requireRejected(t, http.MethodPost, ackURL, headers)
	requireRejected(t, http.MethodPost, nackURL, headers)

	requireNotFound(t, http.MethodGet, publishURL, headers)

	defer kubectlDeleteIgnoreNotFound(t, options, kubeResourcePath)
	k8s.KubectlApply(t, options, kubeResourcePath)

	requireOK(t, http.MethodPost, publishURL, headers)
	requireOK(t, http.MethodPost, pullURL, headers)
	requireOK(t, http.MethodPost, ackURL, headers)
	requireOK(t, http.MethodPost, nackURL, headers)

	requireNotFound(t, http.MethodGet, publishURL, headers)

	k8s.KubectlDelete(t, options, kubeResourcePath)

	requireRejected(t, http.MethodPost, publishURL, headers)
	requireRejected(t, http.MethodPost, pullURL, headers)
	requireRejected(t, http.MethodPost, ackURL, headers)
	requireRejected(t, http.MethodPost, nackURL, headers)

	requireNotFound(t, http.MethodGet, publishURL, headers)
}
