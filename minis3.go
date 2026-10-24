package minis3

import (
	"errors"
	"log"
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

	// listen and fatal are seams for tests.
	listen func(network, address string) (net.Listener, error)
	fatal  func(v ...any)
}

// New creates a new Minis3 server instance.
func New() *Minis3 {
	return &Minis3{
		backend: backend.New(),
		listen:  net.Listen,
		fatal:   log.Fatalln,
	}
}

// Run starts the Minis3 server on a random port.
// It returns the server instance or an error if it failed to start.
// Caller is responsible for calling Close().
func Run() (*Minis3, error) {
	return startNew(New(), "127.0.0.1:0")
}

// startNew starts s on addr, returning nil when it fails to start.
func startNew(s *Minis3, addr string) (*Minis3, error) {
	if err := s.StartAddr(addr); err != nil {
		return nil, err
	}
	return s, nil
}

// Start starts the Minis3 server on a random port.
func (m *Minis3) Start() error {
	return m.StartAddr("127.0.0.1:0")
}

// RunAddr starts the Minis3 server on the provided address.
// It returns the server instance or an error if it failed to start.
// Caller is responsible for calling Close().
func RunAddr(addr string) (*Minis3, error) {
	return startNew(New(), addr)
}

// StartAddr starts the Minis3 server on the provided address.
func (m *Minis3) StartAddr(addr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, err := m.listen("tcp", addr)
	if err != nil {
		return errors.New("failed to listen: " + err.Error())
	}
	m.listener = l

	m.server = &http.Server{
		Handler: m.handler(),
	}

	go func() {
		if err := m.server.Serve(l); err != nil && err != http.ErrServerClosed {
			m.fatal("minis3 server error:", err)
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
