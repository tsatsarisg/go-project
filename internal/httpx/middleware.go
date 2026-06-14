package httpx

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// Recoverer catches panics from downstream handlers, logs them (with stack and
// the request_id carried by the context logger), and returns a generic 500
// JSON body. Without it, net/http recovers the panic per-request but logs to
// raw stderr — bypassing slog/request_id — and sends the client an empty reply.
// Place it early in the chain, after RequestID, so the panic record is
// attributed to the request.
func Recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.ErrorContext(r.Context(), "panic recovered",
						slog.Any("panic", rec),
						slog.String("stack", string(debug.Stack())),
					)
					// Best effort: if the handler already wrote headers this is
					// a no-op write, which is acceptable for a crash path.
					WriteJson(w, http.StatusInternalServerError, Envelope{"error": "internal error"})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestLogger logs each HTTP request's method, path, status, and duration
// at Info level. Pairs with chi.middleware.RequestID upstream so the record
// carries request_id (via the wrapper in logger.go).
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusCapture{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)
			logger.InfoContext(r.Context(), "http request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.status),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}

// statusCapture records the response status code so RequestLogger can log it.
// The zero default is 200 because WriteHeader is optional for 200 OK.
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (s *statusCapture) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
