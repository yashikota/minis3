package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3"
)

// runWithTimeout executes run and reports a hang instead of blocking the
// suite: run waits for an OS signal, so any bug before signal delivery
// (e.g. ignoring a parse error) would otherwise hang until the go test
// timeout. Callers must stub notify to deliver a signal promptly.
func runWithTimeout(
	t *testing.T,
	d deps,
	args []string,
	sigCh chan os.Signal,
) (error, bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- run(d, args, sigCh) }()
	select {
	case err := <-done:
		return err, true
	case <-time.After(10 * time.Second):
		return nil, false
	}
}

func TestRunParseError(t *testing.T) {
	t.Parallel()
	d := defaultDeps()
	err, ok := runWithTimeout(t, d, []string{"-port=not-a-number"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for invalid port")
	}
	if err == nil {
		t.Fatal("run() should fail for invalid port")
	}
}

func TestRunStartError(t *testing.T) {
	t.Parallel()
	d := defaultDeps()
	wantErr := errors.New("start boom")
	d.runAddr = func(string) (*minis3.Minis3, error) {
		return nil, wantErr
	}
	err, ok := runWithTimeout(t, d, []string{"-port=9191"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for start error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want %v", err, wantErr)
	}
}

func TestRunStopError(t *testing.T) {
	t.Parallel()
	d := defaultDeps()
	d.runAddr = func(string) (*minis3.Minis3, error) {
		return &minis3.Minis3{}, nil
	}
	d.addr = func(*minis3.Minis3) string { return "127.0.0.1:9191" }
	d.notify = func(c chan<- os.Signal, _ ...os.Signal) {
		c <- os.Interrupt
	}
	wantErr := errors.New("stop boom")
	d.close = func(*minis3.Minis3) error { return wantErr }

	err, ok := runWithTimeout(t, d, []string{"-port=9191"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for stop error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want %v", err, wantErr)
	}
}

func TestRunSuccess(t *testing.T) {
	t.Parallel()
	d := defaultDeps()
	d.runAddr = func(string) (*minis3.Minis3, error) {
		return &minis3.Minis3{}, nil
	}
	d.addr = func(*minis3.Minis3) string { return "127.0.0.1:9191" }
	d.notify = func(c chan<- os.Signal, _ ...os.Signal) {
		c <- os.Interrupt
	}
	stopped := false
	d.stop = func(chan<- os.Signal) { stopped = true }
	d.close = func(*minis3.Minis3) error { return nil }

	err, ok := runWithTimeout(t, d, []string{"-port=9191"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for success case")
	}
	if err != nil {
		t.Fatalf("run() failed: %v", err)
	}
	if !stopped {
		t.Fatal("expected stop to be called")
	}
}

func TestRunSuccessWithNilSignalChannel(t *testing.T) {
	t.Parallel()
	d := defaultDeps()
	d.runAddr = func(string) (*minis3.Minis3, error) {
		return &minis3.Minis3{}, nil
	}
	d.notify = func(c chan<- os.Signal, _ ...os.Signal) {
		c <- os.Interrupt
	}
	d.stop = func(chan<- os.Signal) {}
	d.printf = func(string, ...any) {}

	err, ok := runWithTimeout(t, d, []string{"-port=9191"}, nil)
	if !ok {
		t.Fatal("run() hung for nil signal channel")
	}
	if err != nil {
		t.Fatalf("run() with nil signal channel failed: %v", err)
	}

	// The created channel must be the one passed to stop, proving run()
	// replaced the nil channel instead of using it.
	var stoppedCh chan<- os.Signal = make(chan os.Signal, 1)
	d.stop = func(c chan<- os.Signal) { stoppedCh = c }
	err, ok = runWithTimeout(t, d, []string{"-port=9191"}, nil)
	if !ok {
		t.Fatal("run() hung for nil signal channel on second run")
	}
	if err != nil {
		t.Fatalf("run() with nil signal channel failed: %v", err)
	}
	if stoppedCh == nil {
		t.Fatal("expected stop to receive the created non-nil channel")
	}
}

func TestMainWithCallsFatalOnError(t *testing.T) {
	t.Parallel()
	d := defaultDeps()
	called := false
	d.fatalf = func(string, ...any) { called = true }
	// main blocks on signals after a successful start, so run it in a
	// goroutine: a hang means the parse error was ignored.
	done := make(chan struct{})
	go func() {
		mainWith(d, []string{"-port=invalid"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("main() hung for invalid port")
	}
	if !called {
		t.Fatal("expected main() to call fatalf on run error")
	}
}

// TestMainRunsWithMainDeps is not parallel: it replaces mainDeps and os.Args.
func TestMainRunsWithMainDeps(t *testing.T) {
	origDeps, origArgs := mainDeps, os.Args
	t.Cleanup(func() { mainDeps, os.Args = origDeps, origArgs })
	var fatal string
	mainDeps = func() deps {
		d := defaultDeps()
		d.fatalf = func(format string, v ...any) { fatal = fmt.Sprintf(format, v...) }
		return d
	}
	os.Args = []string{"minis3", "-port=invalid"}
	main()
	if !strings.Contains(fatal, "invalid") {
		t.Fatalf("main() fatal = %q, want the parse error", fatal)
	}
}
