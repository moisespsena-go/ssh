package ssh

import (
	"io"
	"log"
	"net"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

const (
	ForwardVirtualRequestType       = "virtual-forward"
	CancelForwardVirtualRequestType = "cancel-virtual-forward"
	ForwardedVirtualChannelType     = "forwarded-virtual"
)

type RemoteVirtualForwardRequest struct {
	Name string
}

func (h forwardedHandler) streamVirtual(ctx Context, srv *Server, req *gossh.Request, conn *gossh.ServerConn) (bool, []byte) {
	var (
		reqPayload RemoteVirtualForwardRequest
		err        error
		addr       string
	)
	if err = gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		return false, []byte{}
	}

	addr = "virtual:" + reqPayload.Name
	if srv.ReverseSocketForwardingCallback == nil || !srv.ReverseSocketForwardingCallback(ctx, addr) {
		return false, []byte("virtual socket forwarding is disabled")
	}
	return h.handleVirtualSocket(conn, ctx, srv, reqPayload.Name)
}

func (h forwardedHandler) cancelVirtual(ctx Context, srv *Server, req *gossh.Request, conn *gossh.ServerConn) (bool, []byte) {
	var reqPayload RemoteVirtualForwardRequest
	if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		// TODO: log parse failure
		return false, []byte{}
	}
	if ln, ok := srv.ReverseForwardingRegister.Get(ctx, "virtual:"+reqPayload.Name); ok {
		ln.Close()
	}
	return true, nil
}

func directVirtualHandler(srv *Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	var d struct {
		SocketPath, Reserved0 string
		Reserved1             uint32
	}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	var addr = d.SocketPath

	if srv.SocketForwardingCallback == nil || !srv.SocketForwardingCallback(ctx, addr) {
		newChan.Reject(gossh.Prohibited, "unix socket forwarding is disabled")
		return
	}

	var (
		dest string
	)

	if srv.SocketForwardingResolverCallback != nil {
		var err error
		if dest, err = srv.SocketForwardingResolverCallback(ctx, addr); err != nil {
			newChan.Reject(gossh.ConnectionFailed, "Local forward unix socket resolver failed: "+err.Error())
			return
		}
	} else {
		dest = "unix:" + addr
	}

	socketHandler(srv.Dialer, newChan, ctx, dest)
}

func (h forwardedHandler) handleVirtualSocket(conn *gossh.ServerConn, ctx Context, srv *Server, name string) (bool, []byte) {
	var (
		err error
		ln  net.Listener

		register = srv.ReverseForwardingRegister
	)
	ln, err = srv.ReverseSocketForwardingListenerCallback(ctx, name)

	if err != nil {
		log.Println("listen failed:", err)
		return false, []byte{}
	}

	addr := ln.Addr().String()
	reqAddr := "virtual:" + name

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
			chanType = ForwardedUnixChannelType
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
