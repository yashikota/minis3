package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunParseError(t *testing.T) {
	err := run([]string{"-unknown-flag"})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestRunListenError(t *testing.T) {
	restore := patchGlobals()
	defer restore()

	listenFn = func(_, _ string) (net.Listener, error) {
		return nil, errors.New("listen boom")
	}

	err := run([]string{"-addr=127.0.0.1:9000"})
	if err == nil {
		t.Fatal("expected listen error")
	}
	if !strings.Contains(err.Error(), "failed to listen: listen boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunServeError(t *testing.T) {
	restore := patchGlobals()
	defer restore()

	server := &stubServer{
		serveErr:       errors.New("serve boom"),
		shutdownCalled: make(chan struct{}, 1),
	}
	notifyCh := make(chan chan<- os.Signal, 1)

	listenFn = func(_, _ string) (net.Listener, error) {
		return &stubListener{}, nil
	}
	newHTTPServer = func(http.Handler) httpServer {
		return server
	}
	notifySignal = func(c chan<- os.Signal, _ ...os.Signal) {
		notifyCh <- c
	}
	logPrintfFn = func(string, ...any) {}

	err := run([]string{"-addr=127.0.0.1:9001"})
	if err == nil {
		t.Fatal("expected serve error")
	}
	if !strings.Contains(err.Error(), "server error: serve boom") {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case c := <-notifyCh:
		c <- syscall.SIGTERM
	case <-time.After(time.Second):
		t.Fatal("expected notifySignal to be called")
	}

	select {
	case <-server.shutdownCalled:
	case <-time.After(time.Second):
		t.Fatal("expected Shutdown to be called")
	}
}

func TestRunServeClosedAndShutdownFatal(t *testing.T) {
	restore := patchGlobals()
	defer restore()

	server := &stubServer{
		serveErr:       http.ErrServerClosed,
		shutdownErr:    errors.New("shutdown boom"),
		shutdownCalled: make(chan struct{}, 1),
	}
	notifyCh := make(chan chan<- os.Signal, 1)
	fatalCh := make(chan string, 1)
	printlnCh := make(chan struct{}, 1)

	listenFn = func(_, _ string) (net.Listener, error) {
		return &stubListener{}, nil
	}
	newHTTPServer = func(http.Handler) httpServer {
		return server
	}
	notifySignal = func(c chan<- os.Signal, _ ...os.Signal) {
		notifyCh <- c
	}
	logFatalfFn = func(format string, _ ...any) {
		fatalCh <- format
	}
	logPrintfFn = func(string, ...any) {}
	logPrintlnFn = func(...any) {
		printlnCh <- struct{}{}
	}

	if err := run(nil); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	select {
	case c := <-notifyCh:
		c <- syscall.SIGINT
	case <-time.After(time.Second):
		t.Fatal("expected notifySignal to be called")
	}

	select {
	case <-server.shutdownCalled:
	case <-time.After(time.Second):
		t.Fatal("expected Shutdown to be called")
	}

	select {
	case <-printlnCh:
	case <-time.After(time.Second):
		t.Fatal("expected graceful shutdown log")
	}

	select {
	case format := <-fatalCh:
		if !strings.Contains(format, "Server shutdown failed: %v") {
			t.Fatalf("unexpected fatal format: %q", format)
		}
	case <-time.After(time.Second):
		t.Fatal("expected shutdown fatal log")
	}
}

func TestMainDelegatesToRunFn(t *testing.T) {
	restore := patchGlobals()
	defer restore()

	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"s3-test", "-addr=127.0.0.1:8080"}

	argCh := make(chan []string, 1)
	fatalCh := make(chan string, 1)

	runFn = func(args []string) error {
		argCh <- append([]string(nil), args...)
		return errors.New("run failed")
	}
	logFatalfFn = func(format string, _ ...any) {
		fatalCh <- format
	}

	main()

	select {
	case args := <-argCh:
		if len(args) != 1 || args[0] != "-addr=127.0.0.1:8080" {
			t.Fatalf("unexpected args: %#v", args)
		}
	case <-time.After(time.Second):
		t.Fatal("expected runFn to be called")
	}

	select {
	case format := <-fatalCh:
		if format != "%v" {
			t.Fatalf("unexpected fatal format: %q", format)
		}
	case <-time.After(time.Second):
		t.Fatal("expected logFatalfFn to be called")
	}
}

func TestDefaultNewHTTPServerFactory(t *testing.T) {
	restore := patchGlobals()
	defer restore()

	srv := newHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if _, ok := srv.(*http.Server); !ok {
		t.Fatalf("newHTTPServer() returned %T, want *http.Server", srv)
	}
}

func patchGlobals() func() {
	origListenFn := listenFn
	origNotifySignal := notifySignal
	origNewHTTPServer := newHTTPServer
	origLogFatalfFn := logFatalfFn
	origLogPrintfFn := logPrintfFn
	origLogPrintlnFn := logPrintlnFn
	origRunFn := runFn

	return func() {
		listenFn = origListenFn
		notifySignal = origNotifySignal
		newHTTPServer = origNewHTTPServer
		logFatalfFn = origLogFatalfFn
		logPrintfFn = origLogPrintfFn
		logPrintlnFn = origLogPrintlnFn
		runFn = origRunFn
	}
}

type stubServer struct {
	serveErr       error
	shutdownErr    error
	shutdownCalled chan struct{}
}

func (s *stubServer) Serve(net.Listener) error {
	return s.serveErr
}

func (s *stubServer) Shutdown(context.Context) error {
	if s.shutdownCalled != nil {
		select {
		case s.shutdownCalled <- struct{}{}:
		default:
		}
	}
	return s.shutdownErr
}

type stubListener struct{}

func (*stubListener) Accept() (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (*stubListener) Close() error {
	return nil
}

func (*stubListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
}
