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

// deps are what run and main use from the outside world; tests replace
// them.
type deps struct {
	runAddr func(addr string) (*minis3.Minis3, error)
	addr    func(s *minis3.Minis3) string
	close   func(s *minis3.Minis3) error
	notify  func(c chan<- os.Signal, sig ...os.Signal)
	stop    func(c chan<- os.Signal)
	printf  func(format string, v ...any)
	fatalf  func(format string, v ...any)
}

func defaultDeps() deps {
	return deps{
		runAddr: minis3.RunAddr,
		addr:    func(s *minis3.Minis3) string { return s.Addr() },
		close:   func(s *minis3.Minis3) error { return s.Close() },
		notify:  signal.Notify,
		stop:    signal.Stop,
		printf:  log.Printf,
		fatalf:  log.Fatalf,
	}
}

func run(d deps, args []string, sigCh chan os.Signal) error {
	fs := flag.NewFlagSet("minis3", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", defaultPort, "listen port")
	if err := fs.Parse(args); err != nil {
		return err
	}

	server, err := d.runAddr(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("failed to start minis3: %w", err)
	}
	d.printf("minis3 listening on %s", d.addr(server))

	if sigCh == nil {
		sigCh = make(chan os.Signal, 1)
	}
	d.notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	d.stop(sigCh)

	if err := d.close(server); err != nil {
		return fmt.Errorf("failed to stop minis3: %w", err)
	}
	return nil
}

// mainDeps is main's only seam, so a test can run main itself.
var mainDeps = defaultDeps

func main() {
	mainWith(mainDeps(), os.Args[1:])
}

func mainWith(d deps, args []string) {
	if err := run(d, args, nil); err != nil {
		d.fatalf("%v", err)
	}
}
