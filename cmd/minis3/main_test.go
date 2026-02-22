package main

import (
	"errors"
	"os"
	"testing"

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

func TestRunParseError(t *testing.T) {
	resetMainHooks()
	if err := run([]string{"-port=not-a-number"}, make(chan os.Signal, 1)); err == nil {
		t.Fatal("run() should fail for invalid port")
	}
}

func TestRunStartError(t *testing.T) {
	resetMainHooks()
	wantErr := errors.New("start boom")
	runAddrFn = func(string) (*minis3.Minis3, error) {
		return nil, wantErr
	}
	err := run([]string{"-port=9191"}, make(chan os.Signal, 1))
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

	err := run([]string{"-port=9191"}, make(chan os.Signal, 1))
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

	if err := run([]string{"-port=9191"}, make(chan os.Signal, 1)); err != nil {
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

	if err := run([]string{"-port=9191"}, nil); err != nil {
		t.Fatalf("run() with nil signal channel failed: %v", err)
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
	main()
	if !called {
		t.Fatal("expected main() to call fatalfFn on run error")
	}
}
