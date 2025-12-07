package handler

import (
	"net/http"

	"github.com/yashikota/minis3/internal/backend"
)

// Handler handles HTTP requests for S3 operations.
type Handler struct {
	backend *backend.Backend
}

// New creates a new Handler with the given backend.
func New(b *backend.Backend) *Handler {
	return &Handler{backend: b}
}

// ServeHTTP implements http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handleRequest(w, r)
}

// handleRequest is the main dispatch point.
func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		h.handleService(w, r)
		return
	}

	bucketName, key := extractBucketAndKey(path)

	if key == "" {
		h.handleBucket(w, r, bucketName)
	} else {
		h.handleObject(w, r, bucketName, key)
	}
}

// extractBucketAndKey parses the path into bucket and key components.
func extractBucketAndKey(path string) (string, string) {
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			return path[:i], path[i+1:]
		}
	}
	return path, ""
}
