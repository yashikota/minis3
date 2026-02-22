package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yashikota/minis3"
)

const defaultPort = 9191

func main() {
	port := flag.Int("port", defaultPort, "listen port")
	flag.Parse()

	server, err := minis3.RunAddr(fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to start minis3: %v", err)
	}
	log.Printf("minis3 listening on %s", server.Addr())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	signal.Stop(sigCh)

	if err := server.Close(); err != nil {
		log.Fatalf("failed to stop minis3: %v", err)
	}
}
