package minis3

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/yashikota/minis3/internal/api"
	"github.com/yashikota/minis3/internal/backend"
)

// Minis3 is the main server struct.
type Minis3 struct {
	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
	backend  *backend.Backend
}

// New creates a new Minis3 server instance.
func New() *Minis3 {
	return &Minis3{
		backend: backend.New(),
	}
}

// Run starts the Minis3 server on a random port.
// It returns the server instance or an error if it failed to start.
// Caller is responsible for calling Close().
func Run() (*Minis3, error) {
	s := New()
	if err := s.Start(); err != nil {
		return nil, err
	}
	return s, nil
}

// Start starts the Minis3 server on a random port.
func (m *Minis3) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	m.listener = l

	m.server = &http.Server{
		Handler: m.handler(),
	}

	go func() {
		if err := m.server.Serve(l); err != nil && err != http.ErrServerClosed {
			// In a real app we might want to capture this error channel
			fmt.Printf("minis3 server error: %v\n", err)
		}
	}()

	return nil
}

// Close stops the server.
func (m *Minis3) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil {
		return m.server.Close()
	}
	return nil
}

// Addr returns the address the server is listening on.
func (m *Minis3) Addr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener != nil {
		return m.listener.Addr().String()
	}
	return ""
}

// Host returns the host:port of the server.
func (m *Minis3) Host() string {
	return m.Addr()
}

func (m *Minis3) handler() http.Handler {
	mux := http.NewServeMux()
	// TODO: register handlers
	mux.HandleFunc("/", m.handleRequest)
	return mux
}

// handleRequest is the main dispatch point.
func (m *Minis3) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Basic routing
	// Path: / -> Service (ListBuckets)
	// Path: /bucket -> Bucket (Put, Get, Delete)
	// Path: /bucket/key -> Object (Put, Get, Delete)
	path := r.URL.Path
	if path == "/" {
		m.handleService(w, r)
		return
	}

	// Actually, splitPath should probably return (bucket, key)
	// If path is /bucket, key is ""
	// If path is /bucket/key/foo, key is "key/foo"
	bucketName, key := extractBucketAndKey(path)

	if key == "" {
		m.handleBucket(w, r, bucketName)
	} else {
		m.handleObject(w, r, bucketName, key)
	}
}

func extractBucketAndKey(path string) (string, string) {
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	// Find first slash
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			return path[:i], path[i+1:]
		}
	}
	return path, ""
}

func (m *Minis3) handleService(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		api.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
		return
	}

	list := m.backend.ListBuckets()
	resp := api.ListAllMyBucketsResult{
		Owner: &api.Owner{ID: "minis3", DisplayName: "minis3"},
	}
	for _, b := range list {
		resp.Buckets = append(resp.Buckets, api.BucketInfo{
			Name:         b.Name,
			CreationDate: b.CreationDate.Format(time.RFC3339),
		})
	}

	// Ignore write error because we can't do anything about it if the connection is broken.
	_, _ = w.Write([]byte(xml.Header))
	output, _ := xml.Marshal(resp)
	_, _ = w.Write(output)
}

func (m *Minis3) handleBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	switch r.Method {
	case "PUT":
		err := m.backend.CreateBucket(bucketName)
		if err != nil {
			api.WriteError(w, http.StatusConflict, "BucketAlreadyExists", err.Error())
			return
		}
		w.Header().Set("Location", "/"+bucketName)
		w.WriteHeader(http.StatusOK) // S3 CreateBucket returns 200 OK
	case "DELETE":
		err := m.backend.DeleteBucket(bucketName)
		if err != nil {
			api.WriteError(w, http.StatusConflict, "BucketNotEmpty", err.Error())
			// Note: Real S3 returns NoSuchBucket if not found, BucketNotEmpty if not empty.
			// Our backend returns generic errors, we should probably refine them or check error string.
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "HEAD":
		_, ok := m.backend.GetBucket(bucketName)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		api.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
	}
}

func (m *Minis3) handleObject(w http.ResponseWriter, r *http.Request, bucketName, key string) {
	switch r.Method {
	case "PUT":
		data, err := io.ReadAll(r.Body)
		if err != nil {
			api.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		defer func() { _ = r.Body.Close() }()

		contentType := r.Header.Get("Content-Type")
		obj, err := m.backend.PutObject(bucketName, key, data, contentType)
		if err != nil {
			api.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
			return
		}
		w.Header().Set("ETag", obj.ETag)
		w.WriteHeader(http.StatusOK)

	case "GET":
		obj, ok := m.backend.GetObject(bucketName, key)
		if !ok {
			api.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		// Ignore write error because we can't do anything about it if the connection is broken.
		_, _ = w.Write(obj.Data)

	case "DELETE":
		m.backend.DeleteObject(bucketName, key)
		w.WriteHeader(http.StatusNoContent)

	case "HEAD":
		obj, ok := m.backend.GetObject(bucketName, key)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		w.WriteHeader(http.StatusOK)

	default:
		api.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
	}
}
