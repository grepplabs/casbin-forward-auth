package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestThreeEngines_TwoCollect_OneExposes(t *testing.T) {
	// shared registry for all metrics
	reg := prometheus.NewRegistry()

	// engine 1: collects, namespace "main"
	mwMain, err := NewMiddlewareWithConfig(MiddlewareConfig{
		Namespace:   "main",
		Registerer:  reg,
		IncludeHost: false,
	})
	require.NoError(t, err)

	mainEngine := gin.New()
	mainEngine.Use(GinMiddleware(mwMain))
	mainEngine.GET("/main", func(c *gin.Context) {
		c.String(http.StatusOK, "from main")
	})

	// engine 2: collects, namespace "second"
	mwSecond, err := NewMiddlewareWithConfig(MiddlewareConfig{
		Namespace:   "second",
		Registerer:  reg,
		IncludeHost: false,
	})
	require.NoError(t, err)

	secondEngine := gin.New()
	secondEngine.Use(GinMiddleware(mwSecond))
	secondEngine.GET("/second", func(c *gin.Context) {
		c.String(http.StatusOK, "from second")
	})

	// engine 3: metric engine – does NOT collect, only exposes /metrics
	metricsEngine := gin.New()
	metricsEngine.GET("/metrics", NewHandlerWithConfig(HandlerConfig{
		Gatherer: reg,
	}))

	// hit main engine
	{
		req := httptest.NewRequest(http.MethodGet, "/main", nil)
		w := httptest.NewRecorder()
		mainEngine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// hit second engine
	{
		req := httptest.NewRequest(http.MethodGet, "/second", nil)
		w := httptest.NewRecorder()
		secondEngine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// now scrape ONLY from metric engine
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	metricsEngine.ServeHTTP(metricsRec, metricsReq)

	body := metricsRec.Body.String()
	assert.Equal(t, http.StatusOK, metricsRec.Code)

	// expect metrics from main engine (no host label!)
	assert.Contains(t, body, `main_gin_requests_total{code="200",method="GET",url="/main"} 1`)
	assert.Contains(t, body, `main_gin_request_duration_seconds_count{code="200",method="GET",url="/main"} 1`)

	// expect metrics from second engine (no host label!)
	assert.Contains(t, body, `second_gin_requests_total{code="200",method="GET",url="/second"} 1`)
	assert.Contains(t, body, `second_gin_request_duration_seconds_count{code="200",method="GET",url="/second"} 1`)
}

func TestTwoEnginesSharedRegistry_OnlyOneExports_WithNamespaces(t *testing.T) {
	customRegistry := prometheus.NewRegistry()

	// Middleware for main engine
	mwMain, err := NewMiddlewareWithConfig(MiddlewareConfig{
		Namespace:   "main",
		Registerer:  customRegistry,
		IncludeHost: true,
	})
	require.NoError(t, err)
	// Middleware for second engine (same registry)
	mwSecond, err := NewMiddlewareWithConfig(MiddlewareConfig{
		Namespace:   "second",
		Registerer:  customRegistry,
		IncludeHost: true,
	})
	require.NoError(t, err)

	// --- Engine 1 (main): has /metrics ---
	r1 := gin.New()
	r1.Use(GinMiddleware(mwMain))
	r1.GET("/metrics", NewHandlerWithConfig(HandlerConfig{Gatherer: customRegistry}))
	r1.GET("/main", func(c *gin.Context) {
		c.String(http.StatusOK, "from main engine")
	})

	// --- Engine 2 (second): no /metrics endpoint ---
	r2 := gin.New()
	r2.Use(GinMiddleware(mwSecond))
	r2.GET("/second", func(c *gin.Context) {
		c.String(http.StatusOK, "from second engine")
	})

	// Hit routes on both engines
	{
		req := httptest.NewRequest(http.MethodGet, "/main", nil)
		w := httptest.NewRecorder()
		r1.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
	{
		req := httptest.NewRequest(http.MethodGet, "/second", nil)
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Scrape metrics from engine 1 only
	mreq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mwrec := httptest.NewRecorder()
	r1.ServeHTTP(mwrec, mreq)
	body := mwrec.Body.String()

	assert.Equal(t, http.StatusOK, mwrec.Code)

	// main_* metrics (namespace "main", subsystem "gin")
	assert.Contains(t, body, `main_gin_requests_total{code="200",host="example.com",method="GET",url="/main"} 1`)
	assert.Contains(t, body, `main_gin_request_duration_seconds_count{code="200",host="example.com",method="GET",url="/main"} 1`)

	// second_* metrics (namespace "second", subsystem "gin")
	assert.Contains(t, body, `second_gin_requests_total{code="200",host="example.com",method="GET",url="/second"} 1`)
	assert.Contains(t, body, `second_gin_request_duration_seconds_count{code="200",host="example.com",method="GET",url="/second"} 1`)
}

func TestTwoEnginesSharedRegistry_OnlyOneExports(t *testing.T) {
	customRegistry := prometheus.NewRegistry()

	mw, err := NewMiddlewareWithConfig(MiddlewareConfig{
		Registerer:  customRegistry,
		IncludeHost: true,
	})
	require.NoError(t, err)

	// engine 1: has /metrics
	r1 := gin.New()
	r1.Use(GinMiddleware(mw))
	r1.GET("/metrics", NewHandlerWithConfig(HandlerConfig{Gatherer: customRegistry}))
	r1.GET("/engine1", func(c *gin.Context) {
		c.String(http.StatusOK, "from engine 1")
	})

	// engine 2: no /metrics, but has middleware
	r2 := gin.New()
	r2.Use(GinMiddleware(mw))
	r2.GET("/engine2", func(c *gin.Context) {
		c.String(http.StatusOK, "from engine 2")
	})

	// hit engine1
	{
		req := httptest.NewRequest(http.MethodGet, "/engine1", nil)
		w := httptest.NewRecorder()
		r1.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// hit engine2
	{
		req := httptest.NewRequest(http.MethodGet, "/engine2", nil)
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// now scrape metrics ONLY from engine1
	mreq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mwrec := httptest.NewRecorder()
	r1.ServeHTTP(mwrec, mreq)
	body := mwrec.Body.String()

	assert.Equal(t, http.StatusOK, mwrec.Code)

	// should contain metrics for /engine1
	assert.Contains(t, body, `gin_requests_total{code="200",host="example.com",method="GET",url="/engine1"} 1`)
	assert.Contains(t, body, `gin_request_duration_seconds_count{code="200",host="example.com",method="GET",url="/engine1"} 1`)

	// and also for /engine2 (even though /metrics is not on engine2)
	assert.Contains(t, body, `gin_requests_total{code="200",host="example.com",method="GET",url="/engine2"} 1`)
	assert.Contains(t, body, `gin_request_duration_seconds_count{code="200",host="example.com",method="GET",url="/engine2"} 1`)
}

func TestCustomRegistryMetrics(t *testing.T) {
	r := gin.New()

	customRegistry := prometheus.NewRegistry()

	mw, err := NewMiddlewareWithConfig(MiddlewareConfig{
		Registerer:  customRegistry,
		IncludeHost: true,
	})
	require.NoError(t, err)

	r.Use(GinMiddleware(mw))
	r.GET("/metrics", NewHandlerWithConfig(HandlerConfig{Gatherer: customRegistry}))

	// hit non-existing path -> 404
	req := httptest.NewRequest(http.MethodGet, "/ping?test=1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// read metrics
	mreq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mwrec := httptest.NewRecorder()
	r.ServeHTTP(mwrec, mreq)
	body := mwrec.Body.String()

	assert.Equal(t, http.StatusOK, mwrec.Code)
	assert.Contains(t, body, `gin_request_duration_seconds_count{code="404",host="example.com",method="GET",url="/"} 1`)
}

func TestDefaultRegistryMetrics(t *testing.T) {
	r := gin.New()

	mw, err := NewMiddleware("myapp")
	require.NoError(t, err)

	r.Use(GinMiddleware(mw))
	r.GET("/metrics", NewHandler())

	// 404
	req := httptest.NewRequest(http.MethodGet, "/ping?test=1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// metrics
	mreq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mwrec := httptest.NewRecorder()
	r.ServeHTTP(mwrec, mreq)

	assert.Equal(t, http.StatusOK, mwrec.Code)
	assert.Contains(t, mwrec.Body.String(), `myapp_request_duration_seconds_count{code="404",method="GET",url="/"} 1`)

	unregisterDefaults("myapp")
}

func TestMiddlewareConfig_LabelFuncs(t *testing.T) {
	r := gin.New()
	customRegistry := prometheus.NewRegistry()

	mw, err := NewMiddlewareWithConfig(MiddlewareConfig{
		LabelFuncs: map[string]LabelValueFunc{
			"scheme": func(c *gin.Context, err error) string {
				// gin test requests don't have scheme, just force it
				return "http"
			},
			"method": func(c *gin.Context, err error) string {
				return "overridden_" + c.Request.Method
			},
		},
		Registerer:  customRegistry,
		IncludeHost: true,
	})
	require.NoError(t, err)

	r.Use(GinMiddleware(mw))
	r.GET("/metrics", NewHandlerWithConfig(HandlerConfig{Gatherer: customRegistry}))

	r.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// call it
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// read metrics
	body, code := metricsBody(r, "/metrics")
	assert.Equal(t, http.StatusOK, code)
	// note: scheme="http" from above
	assert.Contains(t, body, `gin_request_duration_seconds_count{code="200",host="example.com",method="overridden_GET",scheme="http",url="/ok"} 1`)
}

func TestMiddlewareConfig_StatusCodeResolver(t *testing.T) {
	r := gin.New()
	customRegistry := prometheus.NewRegistry()

	customResolver := func(c *gin.Context, err error) int {
		if err == nil {
			return c.Writer.Status()
		}
		msg := err.Error()
		if strings.Contains(msg, "NOT FOUND") {
			return http.StatusNotFound
		}
		if strings.Contains(msg, "NOT Authorized") {
			return http.StatusUnauthorized
		}
		return http.StatusInternalServerError
	}

	mw, err := NewMiddlewareWithConfig(MiddlewareConfig{
		Subsystem:          "myapp",
		Registerer:         customRegistry,
		StatusCodeResolver: customResolver,
		IncludeHost:        true,
	})
	require.NoError(t, err)

	r.Use(GinMiddleware(mw))
	r.GET("/metrics", NewHandlerWithConfig(HandlerConfig{Gatherer: customRegistry}))

	r.GET("/handler_for_ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, "OK")
	})
	r.GET("/handler_for_nok", func(c *gin.Context) {
		c.JSON(http.StatusConflict, "NOK")
	})
	r.GET("/handler_for_not_found", func(c *gin.Context) {
		_ = c.Error(errors.New("NOT FOUND"))
		c.Status(http.StatusInternalServerError)
	})
	r.GET("/handler_for_not_authorized", func(c *gin.Context) {
		_ = c.Error(errors.New("NOT Authorized"))
		c.Status(http.StatusInternalServerError)
	})
	r.GET("/handler_for_unknown_error", func(c *gin.Context) {
		_ = c.Error(errors.New("i do not know"))
		c.Status(http.StatusInternalServerError)
	})

	assert.Equal(t, http.StatusOK, perform(r, "/handler_for_ok"))
	assert.Equal(t, http.StatusConflict, perform(r, "/handler_for_nok"))
	assert.Equal(t, http.StatusInternalServerError, perform(r, "/handler_for_not_found"))
	assert.Equal(t, http.StatusInternalServerError, perform(r, "/handler_for_not_authorized"))
	assert.Equal(t, http.StatusInternalServerError, perform(r, "/handler_for_unknown_error"))

	body, code := metricsBody(r, "/metrics")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "myapp_requests_total")
	assert.Contains(t, body, `myapp_requests_total{code="200",host="example.com",method="GET",url="/handler_for_ok"} 1`)
	assert.Contains(t, body, `myapp_requests_total{code="409",host="example.com",method="GET",url="/handler_for_nok"} 1`)
	assert.Contains(t, body, `myapp_requests_total{code="404",host="example.com",method="GET",url="/handler_for_not_found"} 1`)
	assert.Contains(t, body, `myapp_requests_total{code="401",host="example.com",method="GET",url="/handler_for_not_authorized"} 1`)
	assert.Contains(t, body, `myapp_requests_total{code="500",host="example.com",method="GET",url="/handler_for_unknown_error"} 1`)

	unregisterDefaults("myapp")
}

func TestMiddlewareConfig_HistogramOptsFunc(t *testing.T) {
	r := gin.New()
	customRegistry := prometheus.NewRegistry()

	mw, err := NewMiddlewareWithConfig(MiddlewareConfig{
		HistogramOptsFunc: func(opts prometheus.HistogramOpts) prometheus.HistogramOpts {
			if opts.Name == "request_duration_seconds" {
				opts.ConstLabels = prometheus.Labels{"my_const": "123"}
			}
			return opts
		},
		Registerer:  customRegistry,
		IncludeHost: true,
	})
	require.NoError(t, err)

	r.Use(GinMiddleware(mw))
	r.GET("/metrics", NewHandlerWithConfig(HandlerConfig{Gatherer: customRegistry}))

	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, "OK")
	})

	assert.Equal(t, http.StatusOK, perform(r, "/ok"))

	body, code := metricsBody(r, "/metrics")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, `gin_request_duration_seconds_count{code="200",host="example.com",method="GET",my_const="123",url="/ok"} 1`)
}

func TestMiddlewareConfig_CounterOptsFunc(t *testing.T) {
	r := gin.New()
	customRegistry := prometheus.NewRegistry()

	mw, err := NewMiddlewareWithConfig(MiddlewareConfig{
		CounterOptsFunc: func(opts prometheus.CounterOpts) prometheus.CounterOpts {
			if opts.Name == "requests_total" {
				opts.ConstLabels = prometheus.Labels{"my_const": "123"}
			}
			return opts
		},
		Registerer:  customRegistry,
		IncludeHost: true,
	})
	require.NoError(t, err)

	r.Use(GinMiddleware(mw))
	r.GET("/metrics", NewHandlerWithConfig(HandlerConfig{Gatherer: customRegistry}))

	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, "OK")
	})

	assert.Equal(t, http.StatusOK, perform(r, "/ok"))

	body, code := metricsBody(r, "/metrics")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, `gin_requests_total{code="200",host="example.com",method="GET",my_const="123",url="/ok"} 1`)
}

func perform(r *gin.Engine, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func metricsBody(r *gin.Engine, path string) (string, int) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Body.String(), w.Code
}

func unregisterDefaults(subsystem string) {
	p := prometheus.DefaultRegisterer

	unRegisterCollector := func(opts prometheus.Opts) {
		dummy := prometheus.NewCounterVec(prometheus.CounterOpts(opts), []string{"code", "method", "host", "url"})
		err := p.Register(dummy)
		if err == nil {
			return
		}
		var arErr prometheus.AlreadyRegisteredError
		if errors.As(err, &arErr) {
			p.Unregister(arErr.ExistingCollector)
		}
	}

	// requests_total
	unRegisterCollector(prometheus.Opts{
		Subsystem: subsystem,
		Name:      "requests_total",
		Help:      "How many HTTP requests processed, partitioned by status code and HTTP method.",
	})

	// request_duration_seconds
	unRegisterCollector(prometheus.Opts{
		Subsystem: subsystem,
		Name:      "request_duration_seconds",
		Help:      "The HTTP request latencies in seconds.",
	})
}
