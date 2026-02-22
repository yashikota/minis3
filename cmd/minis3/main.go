package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yashikota/minis3"
)

const defaultPort = 9191

var (
	runAddrFn = minis3.RunAddr
	addrFn    = func(s *minis3.Minis3) string { return s.Addr() }
	closeFn   = func(s *minis3.Minis3) error { return s.Close() }
	notifyFn  = signal.Notify
	stopFn    = signal.Stop
	printfFn  = log.Printf
	fatalfFn  = log.Fatalf
)

func run(args []string, sigCh chan os.Signal) error {
	fs := flag.NewFlagSet("minis3", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", defaultPort, "listen port")
	if err := fs.Parse(args); err != nil {
		return err
	}

	server, err := runAddrFn(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("failed to start minis3: %w", err)
	}
	printfFn("minis3 listening on %s", addrFn(server))

	if sigCh == nil {
		sigCh = make(chan os.Signal, 1)
	}
	notifyFn(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	stopFn(sigCh)

	if err := closeFn(server); err != nil {
		return fmt.Errorf("failed to stop minis3: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], nil); err != nil {
		fatalfFn("%v", err)
	}
}
