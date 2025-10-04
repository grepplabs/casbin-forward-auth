
TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY21lL3Byb2plY3QvcHJvamVjdC5pZCI6IjEyMzQ1Njc4OTAxMiIsImF1ZCI6WyJhY21lIiwiYXBpIl0sImF6cCI6Im1pY2hhbC10ZXN0LWFvZXlkODFAc2EuYWNtZS5jbG91ZCIsImVtYWlsIjoibWljaGFsLXRlc3QtYW9leWQ4MUBzYS5hY21lLmNsb3VkIiwiZXhwIjoxNzYwMDMzNTczLCJpYXQiOjE3NjAwMjk5NzMsImlzcyI6ImFjbWUvc2VydmljZWFjY291bnQiLCJqdGkiOiJhMDM5MjNjMS01ZTk5LTQ4OGEtYmQxYS1lMjAxYWY5NTZkMTciLCJzdWIiOiI5ZTRmZGIxYy0zMzQ1LTRjMDctOThkOS03M2I5OTNjOWRkNDIifQ.7In_S9Llms9H_WuBSDLKhEMS-Pk_6U5y-lNrz-rxuU8

run-server:
	go run cmd/casbin-traefik-forward-auth/main.go --auth-route-config-path examples/pubsub-routes-expr.yaml

grant:
	kubectl apply -f examples/pubsub-policy.yaml

revoke:
	kubectl delete -f examples/pubsub-policy.yaml

test-publish:
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/publish" localhost:8080/auth

test-read:
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/pull" localhost:8080/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/ack" localhost:8080/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/nack" localhost:8080/auth

tests: test-publish test-read
