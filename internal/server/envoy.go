package server

import (
	"context"
	"fmt"
	"net"
	"net/http"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gin-gonic/gin"
	"github.com/grepplabs/loggo/zlog"
	grpcprom "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	grpcrecovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
)

const (
	errorBodyRejected = `{"error":"rejected"}`
	errorBodyNotFound = `{"error":"404 page not found"}`
)

type EnvoyAuthorizationServer struct {
	grpcServer *grpc.Server
}

func NewEnvoyAuthorizationServer(authEngine *gin.Engine, registry *prometheus.Registry) *EnvoyAuthorizationServer {
	srvMetrics := grpcprom.NewServerMetrics(
		grpcprom.WithServerHandlingTimeHistogram(
			grpcprom.WithHistogramBuckets([]float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10}),
		),
	)
	registry.MustRegister(srvMetrics)

	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
		logging.WithLevels(func(code codes.Code) logging.Level {
			if code == codes.OK {
				return logging.LevelDebug
			}
			return logging.DefaultServerCodeToLevel(code)
		}),
	}
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logging.UnaryServerInterceptor(grpcInterceptorLogger(), loggingOpts...),
			grpcrecovery.UnaryServerInterceptor(),
			srvMetrics.UnaryServerInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			logging.StreamServerInterceptor(grpcInterceptorLogger(), loggingOpts...),
			grpcrecovery.StreamServerInterceptor(),
			srvMetrics.StreamServerInterceptor(),
		),
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
	)

	reflection.Register(grpcServer)
	authv3.RegisterAuthorizationServer(grpcServer, newAuthorizationService(authEngine))
	return &EnvoyAuthorizationServer{
		grpcServer: grpcServer,
	}
}

func (s *EnvoyAuthorizationServer) RunListener(ln net.Listener) error {
	return s.grpcServer.Serve(ln)
}

func grpcInterceptorLogger() logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		switch lvl {
		case logging.LevelDebug:
			zlog.DebugCw(ctx, msg, fields...)
		case logging.LevelInfo:
			zlog.InfoCw(ctx, msg, fields...)
		case logging.LevelWarn:
			zlog.WarnCw(ctx, msg, fields...)
		case logging.LevelError:
			zlog.ErrorCw(ctx, msg, fields...)
		default:
			zlog.ErrorCw(ctx, msg, fields...)
		}
	})
}

type authorizationServer struct {
	authv3.UnimplementedAuthorizationServer
	authEngine *gin.Engine
}

func newAuthorizationService(authEngine *gin.Engine) *authorizationServer {
	return &authorizationServer{authEngine: authEngine}
}

func (s *authorizationServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	code, hdr, err := s.performForwardAuth(ctx, req)
	if err != nil {
		return envoyAuthDeny(typev3.StatusCode_Forbidden, nil, err.Error(), err.Error()), nil
	}
	headers := toEnvoyHeaders(hdr)
	switch code {
	case http.StatusOK:
		return envoyAuthAllow(headers), nil
	case http.StatusNotFound:
		return envoyAuthDeny(typev3.StatusCode_Forbidden, headers, "not found", errorBodyNotFound), nil
	case http.StatusUnauthorized:
		return envoyAuthDeny(typev3.StatusCode_Unauthorized, headers, "unauthorized", errorBodyRejected), nil
	case http.StatusForbidden:
		return envoyAuthDeny(typev3.StatusCode_Forbidden, headers, "forbidden", errorBodyRejected), nil
	default:
		return envoyAuthDeny(typev3.StatusCode_Forbidden, headers, "access denied", errorBodyRejected), nil
	}
}

func (s *authorizationServer) performForwardAuth(ctx context.Context, req *authv3.CheckRequest) (int, map[string]string, error) {
	attrHttp := req.GetAttributes().GetRequest().GetHttp()

	method := attrHttp.GetMethod()
	host := attrHttp.GetHost()
	if host == "" {
		h := attrHttp.GetHeaders()
		if v := h[":authority"]; v != "" {
			host = v
		} else if v := h["host"]; v != "" {
			host = v
		}
	}
	if method == "" || host == "" {
		return 0, nil, fmt.Errorf("missing required headers for forward auth: method=%q host=%q", method, host)
	}

	forwardedUri := attrHttp.GetPath()
	if forwardedUri == "" {
		forwardedUri = "/"
	}

	lw := zlog.Logger.WithValues("method", method, "host", host, "uri", forwardedUri)
	lw.V(1).Info("envoy forward auth")

	code, headers, err := doForwardAuthHTTP(ctx, s.authEngine, method, host, forwardedUri, httpHeaderFromEnvoyHeaders(attrHttp.GetHeaders()))
	if err != nil {
		lw.Error(err, "envoy forward auth error")
	} else if code != http.StatusOK {
		lw.V(1).Info("envoy forward auth rejected", "code", code)
	}
	return code, headers, err
}

func httpHeaderFromEnvoyHeaders(m map[string]string) http.Header {
	h := make(http.Header)
	for k, v := range m {
		// HTTP/2 pseudo-headers are illegal in http.Header
		if k == "" || k[0] == ':' {
			continue
		}
		h[http.CanonicalHeaderKey(k)] = []string{v}
	}
	return h
}

func envoyAuthAllow(headers []*corev3.HeaderValueOption) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

func envoyAuthDeny(code typev3.StatusCode, headers []*corev3.HeaderValueOption, message, body string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.PermissionDenied),
			Message: message,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: code},
				Headers: headers,
				Body:    body,
			},
		},
	}
}

func toEnvoyHeaders(h map[string]string) []*corev3.HeaderValueOption {
	if len(h) == 0 {
		return nil
	}
	out := make([]*corev3.HeaderValueOption, 0, len(h))
	for k, v := range h {
		if k == "" {
			continue
		}
		out = append(out, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: k, Value: v},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return out
}
