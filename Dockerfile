FROM --platform=${BUILDPLATFORM} golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# copy the Go source (relies on .dockerignore to filter)
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -ldflags="-s -w" -o casbin-traefik-forward-auth cmd/casbin-traefik-forward-auth/main.go

FROM --platform=${BUILDPLATFORM} gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/casbin-traefik-forward-auth .
USER 65532:65532

ENTRYPOINT ["/casbin-traefik-forward-auth"]
