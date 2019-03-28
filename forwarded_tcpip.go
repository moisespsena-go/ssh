package ssh

import (
	"io"
	"log"
	"net"
	"strconv"

	gossh "golang.org/x/crypto/ssh"
)

const (
	ForwardTCPIPRequestType       = "tcpip-forward"
	CancelForwardTCPIPRequestType = "cancel-tcpip-forward"

	DirectTCPIPChannelType   = "direct-tcpip"
	ForwardedTCPChannelType  = "forwarded-tcpip"
	ForwardedUnixChannelType = "forwarded-streamlocal@openssh.com"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func (h forwardedHandler) handleTCPIP(conn *gossh.ServerConn, ctx Context, srv *Server, reqAddr string) (bool, []byte) {
	var (
		err error
		ln  net.Listener

		register = srv.ReverseForwardingRegister
	)
	if srv.ReverseSocketForwardingListenerCallback != nil {
		ln, err = srv.ReverseSocketForwardingListenerCallback(ctx, reqAddr)
	} else {
		ln, err = net.Listen("tcp", reqAddr)
	}

	if err != nil {
		log.Println("listen failed:", err)
		return false, []byte{}
	}

	addr := ln.Addr().String()

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

			chanType = ForwardedTCPChannelType
			_, destPortStr, _ := net.SplitHostPort(addr)
			destPort, _ := strconv.Atoi(destPortStr)
			reqBindAdd, _, _ := net.SplitHostPort(reqAddr)
			originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
			originPort, _ := strconv.Atoi(orignPortStr)
			payload = gossh.Marshal(&remoteForwardChannelData{
				DestAddr:   reqBindAdd,
				DestPort:   uint32(destPort),
				OriginAddr: originAddr,
				OriginPort: uint32(originPort),
			})

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

	_, destPortStr, _ := net.SplitHostPort(addr)
	destPort, _ := strconv.Atoi(destPortStr)
	payload := gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})

	return true, payload
}

func directTcpipHandler(srv *Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	addr := net.JoinHostPort(d.DestAddr, strconv.Itoa(int(d.DestPort)))

	if srv.SocketForwardingCallback == nil || !srv.SocketForwardingCallback(ctx, addr) {
		newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	var dest string

	if srv.SocketForwardingResolverCallback != nil {
		var err error
		if dest, err = srv.SocketForwardingResolverCallback(ctx, addr); err != nil {
			newChan.Reject(gossh.ConnectionFailed, "Local forward port resolver failed: "+err.Error())
			return
		}
	} else {
		dest = net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))
	}

	socketHandler(srv.Dialer, newChan, ctx, dest)
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type TCPAddr struct {
	IPAddr   *net.IPAddr
	UnixAddr *net.UnixAddr
}

func (addr TCPAddr) Network() string {
	if addr.IsUnix() {
		return addr.UnixAddr.Network()
	}
	return addr.IPAddr.Network()
}

func (addr TCPAddr) String() string {
	if addr.IsUnix() {
		return addr.UnixAddr.String()
	}
	return addr.IPAddr.String()
}

func (addr TCPAddr) IsUnix() bool {
	return addr.UnixAddr != nil
}

func (h forwardedHandler) streamTCPIP(ctx Context, srv *Server, req *gossh.Request, conn *gossh.ServerConn) (bool, []byte) {
	var (
		reqPayload remoteForwardRequest
		err        error
		addr       string
	)
	if err = gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		// TODO: log parse failure
		return false, []byte{}
	}
	addr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	if srv.ReverseSocketForwardingCallback == nil || !srv.ReverseSocketForwardingCallback(ctx, addr) {
		return false, []byte("port forwarding is disabled")
	}
	return h.handleTCPIP(conn, ctx, srv, addr)
}

func (h forwardedHandler) cancelTCPIP(ctx Context, srv *Server, req *gossh.Request, conn *gossh.ServerConn) (bool, []byte) {
	var reqPayload remoteForwardCancelRequest
	if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		// TODO: log parse failure
		return false, []byte{}
	}
	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	if ln, ok := srv.ReverseForwardingRegister.Get(ctx, addr); ok {
		ln.Close()
	}
	return true, nil
}
