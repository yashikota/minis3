package minis3

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/yashikota/minis3/internal/backend"
	"github.com/yashikota/minis3/internal/handler"
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
	return handler.New(m.backend)
}
