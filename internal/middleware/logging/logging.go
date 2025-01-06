package logging

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Middleware struct {
	log *zap.Logger
}

func New(log *zap.Logger) Middleware {
	return Middleware{
		log: log,
	}
}

// HTTPMiddleware adapts the gRPC middleware to work with HTTP requests
func (m Middleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Extract relevant metadata (you might want to parse custom headers)
		correlationID := r.Header.Get("X-Correlation-ID")
		userAgent := r.Header.Get("User-Agent")
		method := r.Method
		path := r.URL.Path

		if correlationID == "" {
			correlationID = uuid.NewString()
		}

		m.log.With(
			zap.String("method", method),
			zap.String("path", path),
			zap.String("user-agent", userAgent),
			zap.String("x-correlation-id", correlationID),
		).Info("Received incoming request")

		// Call the next middleware/handler in the chain
		next.ServeHTTP(w, r)

		m.log.With(
			zap.String("method", method),
			zap.String("path", path),
			zap.String("user-agent", userAgent),
			zap.String("x-correlation-id", correlationID),
			zap.Duration("latency", time.Since(start)),
		).Info("Processed incoming request")
	})
}
