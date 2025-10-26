# casbin-traefik-forward-auth
A ForwardAuth service for Traefik with Casbin-based authorization.


TODO:
- [ ] e2e with traefik and kubernetes
  - [ ] rbac model
  - [ ] keymatch model
- [ ] github actions docker + helm 
- [ ] README documentation
  - [ ] architecture excalidraw.com
  - [ ] examples with rbac and keymatch
  - [ ] helm chart parameters
- [ ] prometheus metrics
- [ ] optional own jwt - return in `X-` header 
- [ ] optional header jwt validator / oidc
- [ ] tls + cert manager (cert source)
  - [ ] separate (unprotected) health and metrics port
