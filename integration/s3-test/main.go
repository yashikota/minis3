package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yashikota/minis3/internal/backend"
	"github.com/yashikota/minis3/internal/handler"
)

type httpServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

var (
	listenFn      = net.Listen
	notifySignal  = signal.Notify
	newHTTPServer = func(h http.Handler) httpServer { return &http.Server{Handler: h} }
	logFatalfFn   = log.Fatalf
	logPrintfFn   = log.Printf
	logPrintlnFn  = log.Println
	runFn         = run
)

func main() {
	if err := runFn(os.Args[1:]); err != nil {
		logFatalfFn("%v", err)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("minis3-s3-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "0.0.0.0:9000", "Address to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	b := backend.New()
	h := handler.New(b)

	listener, err := listenFn("tcp", *addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	server := newHTTPServer(h)

	go func() {
		sigChan := make(chan os.Signal, 1)
		notifySignal(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logPrintlnFn("Shutting down server gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logFatalfFn("Server shutdown failed: %v", err)
		}
	}()

	logPrintfFn("minis3 listening on %s", *addr)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
