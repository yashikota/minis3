package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/yashikota/minis3"
)

var (
	defaultRunAddrFn = runAddrFn
	defaultAddrFn    = addrFn
	defaultCloseFn   = closeFn
	defaultNotifyFn  = notifyFn
	defaultStopFn    = stopFn
	defaultPrintfFn  = printfFn
	defaultFatalfFn  = fatalfFn
)

func resetMainHooks() {
	runAddrFn = defaultRunAddrFn
	addrFn = defaultAddrFn
	closeFn = defaultCloseFn
	notifyFn = defaultNotifyFn
	stopFn = defaultStopFn
	printfFn = defaultPrintfFn
	fatalfFn = defaultFatalfFn
}

// runWithTimeout executes run and reports a hang instead of blocking the
// suite: run waits for an OS signal, so any bug before signal delivery
// (e.g. ignoring a parse error) would otherwise hang until the go test
// timeout. Callers must stub notifyFn to deliver a signal promptly.
func runWithTimeout(
	t *testing.T,
	args []string,
	sigCh chan os.Signal,
) (error, bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- run(args, sigCh) }()
	select {
	case err := <-done:
		return err, true
	case <-time.After(10 * time.Second):
		return nil, false
	}
}

func TestRunParseError(t *testing.T) {
	resetMainHooks()
	err, ok := runWithTimeout(t, []string{"-port=not-a-number"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for invalid port")
	}
	if err == nil {
		t.Fatal("run() should fail for invalid port")
	}
}

func TestRunStartError(t *testing.T) {
	resetMainHooks()
	wantErr := errors.New("start boom")
	runAddrFn = func(string) (*minis3.Minis3, error) {
		return nil, wantErr
	}
	err, ok := runWithTimeout(t, []string{"-port=9191"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for start error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want %v", err, wantErr)
	}
}

func TestRunStopError(t *testing.T) {
	resetMainHooks()
	runAddrFn = func(string) (*minis3.Minis3, error) {
		return &minis3.Minis3{}, nil
	}
	addrFn = func(*minis3.Minis3) string { return "127.0.0.1:9191" }
	notifyFn = func(c chan<- os.Signal, _ ...os.Signal) {
		c <- os.Interrupt
	}
	wantErr := errors.New("stop boom")
	closeFn = func(*minis3.Minis3) error { return wantErr }

	err, ok := runWithTimeout(t, []string{"-port=9191"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for stop error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want %v", err, wantErr)
	}
}

func TestRunSuccess(t *testing.T) {
	resetMainHooks()
	runAddrFn = func(string) (*minis3.Minis3, error) {
		return &minis3.Minis3{}, nil
	}
	addrFn = func(*minis3.Minis3) string { return "127.0.0.1:9191" }
	notifyFn = func(c chan<- os.Signal, _ ...os.Signal) {
		c <- os.Interrupt
	}
	stopped := false
	stopFn = func(chan<- os.Signal) { stopped = true }
	closeFn = func(*minis3.Minis3) error { return nil }

	err, ok := runWithTimeout(t, []string{"-port=9191"}, make(chan os.Signal, 1))
	if !ok {
		t.Fatal("run() hung for success case")
	}
	if err != nil {
		t.Fatalf("run() failed: %v", err)
	}
	if !stopped {
		t.Fatal("expected stopFn to be called")
	}
}

func TestRunSuccessWithNilSignalChannel(t *testing.T) {
	resetMainHooks()
	runAddrFn = func(string) (*minis3.Minis3, error) {
		return &minis3.Minis3{}, nil
	}
	notifyFn = func(c chan<- os.Signal, _ ...os.Signal) {
		c <- os.Interrupt
	}
	stopFn = func(chan<- os.Signal) {}
	printfFn = func(string, ...any) {}

	err, ok := runWithTimeout(t, []string{"-port=9191"}, nil)
	if !ok {
		t.Fatal("run() hung for nil signal channel")
	}
	if err != nil {
		t.Fatalf("run() with nil signal channel failed: %v", err)
	}

	// The created channel must be the one passed to stopFn, proving run()
	// replaced the nil channel instead of using it.
	var stoppedCh chan<- os.Signal = make(chan os.Signal, 1)
	stopFn = func(c chan<- os.Signal) { stoppedCh = c }
	err, ok = runWithTimeout(t, []string{"-port=9191"}, nil)
	if !ok {
		t.Fatal("run() hung for nil signal channel on second run")
	}
	if err != nil {
		t.Fatalf("run() with nil signal channel failed: %v", err)
	}
	if stoppedCh == nil {
		t.Fatal("expected stopFn to receive the created non-nil channel")
	}
}

func TestMainCallsFatalOnError(t *testing.T) {
	resetMainHooks()
	origArgs := os.Args
	os.Args = []string{"minis3", "-port=invalid"}
	defer func() {
		os.Args = origArgs
	}()

	called := false
	fatalfFn = func(string, ...any) { called = true }
	// main blocks on signals after a successful start, so run it in a
	// goroutine: a hang means the parse error was ignored.
	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("main() hung for invalid port")
	}
	if !called {
		t.Fatal("expected main() to call fatalfFn on run error")
	}
}
