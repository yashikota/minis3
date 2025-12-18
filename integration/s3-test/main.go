package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/yashikota/minis3/internal/backend"
	"github.com/yashikota/minis3/internal/handler"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:9000", "Address to listen on")
	flag.Parse()

	b := backend.New()
	h := handler.New(b)

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	server := &http.Server{Handler: h}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		_ = server.Close()
	}()

	log.Printf("minis3 listening on %s", *addr)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
