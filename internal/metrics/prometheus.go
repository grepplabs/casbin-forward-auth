package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultSubsystem = "gin"
)

type HandlerFunc func(c *gin.Context) error

type MiddlewareFunc func(next HandlerFunc) HandlerFunc

type MiddlewareConfig struct {
	Namespace          string
	Subsystem          string
	IncludeHost        bool
	LabelFuncs         map[string]LabelValueFunc
	HistogramOptsFunc  func(opts prometheus.HistogramOpts) prometheus.HistogramOpts
	CounterOptsFunc    func(opts prometheus.CounterOpts) prometheus.CounterOpts
	Registerer         prometheus.Registerer
	timeNow            func() time.Time
	StatusCodeResolver func(c *gin.Context, err error) int
}

type LabelValueFunc func(c *gin.Context, err error) string

type HandlerConfig struct {
	Gatherer prometheus.Gatherer
}

func NewHandler() gin.HandlerFunc {
	return NewHandlerWithConfig(HandlerConfig{})
}

func NewHandlerWithConfig(config HandlerConfig) gin.HandlerFunc {
	if config.Gatherer == nil {
		config.Gatherer = prometheus.DefaultGatherer
	}
	h := promhttp.HandlerFor(config.Gatherer, promhttp.HandlerOpts{DisableCompression: true})

	if r, ok := config.Gatherer.(prometheus.Registerer); ok {
		h = promhttp.InstrumentMetricHandler(r, h)
	}
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func NewMiddleware(subsystem string) (MiddlewareFunc, error) {
	return NewMiddlewareWithConfig(MiddlewareConfig{Subsystem: subsystem})
}

func NewMiddlewareWithConfig(config MiddlewareConfig) (MiddlewareFunc, error) {
	return config.ToMiddleware()
}

func GinMiddleware(m MiddlewareFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		next := func(ctx *gin.Context) error {
			ctx.Next()
			if len(ctx.Errors) > 0 {
				return ctx.Errors[0]
			}
			return nil
		}

		handler := m(next)
		if err := handler(c); err != nil {
			_ = c.Error(err)
		}
	}
}

// nolint:cyclop,funlen
func (conf MiddlewareConfig) ToMiddleware() (MiddlewareFunc, error) {
	if conf.timeNow == nil {
		conf.timeNow = time.Now
	}
	if conf.Subsystem == "" {
		conf.Subsystem = defaultSubsystem
	}
	if conf.Registerer == nil {
		conf.Registerer = prometheus.DefaultRegisterer
	}
	if conf.CounterOptsFunc == nil {
		conf.CounterOptsFunc = func(opts prometheus.CounterOpts) prometheus.CounterOpts {
			return opts
		}
	}
	if conf.HistogramOptsFunc == nil {
		conf.HistogramOptsFunc = func(opts prometheus.HistogramOpts) prometheus.HistogramOpts {
			return opts
		}
	}
	if conf.StatusCodeResolver == nil {
		conf.StatusCodeResolver = defaultStatusResolver
	}

	baseLabels := []string{"code", "method", "url"}
	if conf.IncludeHost {
		baseLabels = append(baseLabels, "host")
	}
	labelNames, customValuers := createLabels(baseLabels, conf.LabelFuncs)

	requestCount := prometheus.NewCounterVec(
		conf.CounterOptsFunc(prometheus.CounterOpts{
			Namespace: conf.Namespace,
			Subsystem: conf.Subsystem,
			Name:      "requests_total",
			Help:      "How many HTTP requests processed, partitioned by status code and HTTP method.",
		}),
		labelNames,
	)
	if err := conf.Registerer.Register(requestCount); err != nil {
		return nil, err
	}

	requestDuration := prometheus.NewHistogramVec(
		conf.HistogramOptsFunc(prometheus.HistogramOpts{
			Namespace: conf.Namespace,
			Subsystem: conf.Subsystem,
			Name:      "request_duration_seconds",
			Help:      "The HTTP request latencies in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
		labelNames,
	)
	if err := conf.Registerer.Register(requestDuration); err != nil {
		return nil, err
	}

	return func(next HandlerFunc) HandlerFunc {
		return func(c *gin.Context) error {
			start := conf.timeNow()
			err := next(c)
			elapsed := float64(conf.timeNow().Sub(start)) / float64(time.Second)

			url := c.FullPath()
			if url == "" {
				url = "/"
			}
			status := conf.StatusCodeResolver(c, err)
			values := make([]string, len(labelNames))
			for i, name := range labelNames {
				switch name {
				case "code":
					values[i] = strconv.Itoa(status)
				case "method":
					values[i] = c.Request.Method
				case "host":
					values[i] = c.Request.Host
				case "url":
					values[i] = strings.ToValidUTF8(url, "\uFFFD")
				}
			}
			for _, cv := range customValuers {
				values[cv.index] = cv.valueFunc(c, err)
			}
			if obs, err := requestDuration.GetMetricWithLabelValues(values...); err == nil {
				obs.Observe(elapsed)
			} else {
				return fmt.Errorf("failed to label request duration metric with values, err: %w", err)
			}
			if obs, err := requestCount.GetMetricWithLabelValues(values...); err == nil {
				obs.Inc()
			} else {
				return fmt.Errorf("failed to label request count metric with values, err: %w", err)
			}
			return err
		}
	}, nil
}

type customLabelValuer struct {
	index     int
	label     string
	valueFunc LabelValueFunc
}

func createLabels(baseLabels []string, customLabelFuncs map[string]LabelValueFunc) ([]string, []customLabelValuer) {
	labelNames := append([]string(nil), baseLabels...)

	if len(customLabelFuncs) == 0 {
		return labelNames, nil
	}
	customValuers := make([]customLabelValuer, 0, len(customLabelFuncs))
	for label, labelFunc := range customLabelFuncs {
		customValuers = append(customValuers, customLabelValuer{
			label:     label,
			valueFunc: labelFunc,
		})
	}

	// deterministic order for custom labels
	sort.Slice(customValuers, func(i, j int) bool {
		return customValuers[i].label < customValuers[j].label
	})

	for i, cv := range customValuers {
		idx := containsAt(labelNames, cv.label)
		if idx == -1 {
			idx = len(labelNames)
			labelNames = append(labelNames, cv.label)
		}
		customValuers[i].index = idx
	}

	return labelNames, customValuers
}

func containsAt[K comparable](haystack []K, needle K) int {
	for i, v := range haystack {
		if v == needle {
			return i
		}
	}
	return -1
}

func defaultStatusResolver(c *gin.Context, err error) int {
	status := c.Writer.Status()
	if err != nil {
		if status == 0 || status == http.StatusOK {
			status = http.StatusInternalServerError
		}
	}
	if status == 0 {
		status = http.StatusOK
	}
	return status
}
