package ssh

import (
	"io"
	"log"
	"net"

	gossh "golang.org/x/crypto/ssh"
)

type forwardedHandler struct {
}

func (h forwardedHandler) HandleRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	switch req.Type {
	case OpenSSHStreamLocalForward:
		return h.streamUnix(ctx, srv, req, conn)

	case OpenSSHCancelStreamLocalForward:
		return h.cancelUnix(ctx, srv, req, conn)

	case ForwardTCPIPRequestType:
		return h.streamTCPIP(ctx, srv, req, conn)

	case CancelForwardTCPIPRequestType:
		return h.cancelTCPIP(ctx, srv, req, conn)

	case ForwardVirtualRequestType:
		return h.streamVirtual(ctx, srv, req, conn)

	case CancelForwardVirtualRequestType:
		return h.cancelVirtual(ctx, srv, req, conn)

	default:
		return false, nil
	}
}

func socketHandler(dialer Dialer, newChan gossh.NewChannel, ctx Context, addr string) {
	var (
		err error
		con net.Conn
	)

	if con, err = dialer.Dial(addr, ctx); err != nil {
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		log.Printf("dial to %q failed: %v", addr, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		con.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer con.Close()
		io.Copy(ch, con)
	}()
	go func() {
		defer ch.Close()
		defer con.Close()
		io.Copy(con, ch)
	}()
}
