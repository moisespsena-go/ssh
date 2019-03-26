package ssh

import (
	"io"
	"log"
	"net"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

const (
	OpenSSHStreamLocalForward       = "streamlocal-forward@openssh.com"
	OpenSSHCancelStreamLocalForward = "cancel-" + OpenSSHStreamLocalForward
)

func directUnixHandler(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	var d struct {
		SocketPath, Reserved0 string
		Reserved1             uint32
	}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	var addr = d.SocketPath

	if srv.LocalUnixSocketForwardingCallback == nil || !srv.LocalUnixSocketForwardingCallback(ctx, addr) {
		newChan.Reject(gossh.Prohibited, "unix socket forwarding is disabled")
		return
	}

	var (
		dest string
	)

	if srv.LocalUnixSocketForwardingResolverCallback != nil {
		var err error
		if dest, err = srv.LocalUnixSocketForwardingResolverCallback(ctx, addr); err != nil {
			newChan.Reject(gossh.ConnectionFailed, "Local forward unix socket resolver failed: "+err.Error())
			return
		}
	} else {
		dest = "unix:" + addr
	}

	portOrUnixSocketHandler(newChan, ctx, dest)
}

func (h forwardedTCPHandler) handleUnixSocket(conn *gossh.ServerConn, ctx Context, srv *Server, pth string) (bool, []byte) {
	var (
		err error
		ln  net.Listener

		register = srv.ReverseForwardingRegister
	)
	if srv.ReverseUnixSocketForwardingListenerCallback != nil {
		ln, err = srv.ReverseUnixSocketForwardingListenerCallback(ctx, pth)
	} else {
		if _, err := os.Stat(pth); err != nil {
			if !os.IsNotExist(err) {
				log.Println("stat of unix addr", pth, "addr failed:", err)
				return false, []byte{}
			}
		} else if err := os.Remove(pth); err != nil {
			log.Println("remove unix sockfile", pth, "failed:", err)
			return false, []byte{}
		}
		ln, err = net.Listen("unix", pth)
	}

	if err != nil {
		log.Println("listen failed:", err)
		return false, []byte{}
	}

	addr := ln.Addr().String()
	reqAddr := "unix:" + pth

	if err = register.Register(ctx, reqAddr, ln); err != nil {
		log.Println("register listener of `"+reqAddr+"` failed:", err)
		ln.Close()
		return false, nil
	}

	go func() {
		<-ctx.Done()
		ln, ok := register.Get(ctx, addr)
		if ok {
			ln.Close()
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				// TODO: log accept failure
				break
			}
			var (
				payload  []byte
				chanType string
			)
			chanType = forwardedUnixChannelType
			payload = gossh.Marshal(struct{ a, b string }{a: strings.TrimPrefix(reqAddr, "unix:")})

			go func() {
				ch, reqs, err := conn.OpenChannel(chanType, payload)
				if err != nil {
					// TODO: log failure to open channel
					log.Println(err)
					c.Close()
					return
				}
				go gossh.DiscardRequests(reqs)
				go func() {
					defer ch.Close()
					defer c.Close()
					io.Copy(ch, c)
				}()
				go func() {
					defer ch.Close()
					defer c.Close()
					io.Copy(c, ch)
				}()
			}()
		}
		register.UnRegister(ctx, addr)
	}()

	return true, nil
}
