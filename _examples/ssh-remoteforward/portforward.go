package main

import (
	"io"
	"log"
	"net"

	"github.com/gliderlabs/ssh"
)

func main() {

	log.Println("starting ssh server on port 2222...")

	server := ssh.Server{
		SocketForwardingCallback: ssh.SocketForwardingCallback(func(ctx ssh.Context, addr string) bool {
			dhost, dport, _ := net.SplitHostPort(addr)
			log.Println("Accepted forward", dhost, dport)
			return true
		}),
		Addr: ":2222",
		Handler: ssh.Handler(func(s ssh.Session) {
			io.WriteString(s, "Remote forwarding available...\n")
			select {}
		}),
		ReverseSocketForwardingCallback: ssh.ReverseSocketForwardingCallback(func(ctx ssh.Context, addr string) bool {
			host, port, _ := net.SplitHostPort(addr)
			log.Println("attempt to bind", host, port, "granted")
			return true
		}),
	}

	log.Fatal(server.ListenAndServe())
}
