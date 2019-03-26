package ssh

import (
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedTCPChannelType  = "forwarded-tcpip"
	forwardedUnixChannelType = "forwarded-streamlocal@openssh.com"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func portOrUnixSocketHandler(newChan gossh.NewChannel, ctx Context, dest string) {
	var (
		err   error
		dconn net.Conn
	)

	if strings.HasPrefix(dest, "unix:") {
		var dialer net.Dialer
		dconn, err = dialer.DialContext(ctx, "unix", strings.TrimPrefix(dest, "unix:"))
		if err != nil {
			newChan.Reject(gossh.ConnectionFailed, err.Error())
			return
		}
	} else {
		var dialer net.Dialer
		dconn, err = dialer.DialContext(ctx, "tcp", dest)
		if err != nil {
			newChan.Reject(gossh.ConnectionFailed, err.Error())
			return
		}
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
	}()
}

func directTcpipHandler(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	addr := net.JoinHostPort(d.DestAddr, strconv.Itoa(int(d.DestPort)))

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, addr) {
		newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	var dest string

	if srv.LocalPortForwardingResolverCallback != nil {
		var err error
		if dest, err = srv.LocalPortForwardingResolverCallback(ctx, addr); err != nil {
			newChan.Reject(gossh.ConnectionFailed, "Local forward port resolver failed: "+err.Error())
			return
		}
	} else {
		dest = net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))
	}

	portOrUnixSocketHandler(newChan, ctx, dest)
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteUnixForwardRequest struct {
	SocketPath string
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

type forwardedTCPHandler struct {
}

func (h forwardedTCPHandler) handleAddr(conn *gossh.ServerConn, ctx Context, srv *Server, reqAddr string) (bool, []byte) {
	var (
		err error
		ln  net.Listener

		register = srv.ReverseForwardingRegister
	)
	if srv.ReversePortForwardingListenerCallback != nil {
		ln, err = srv.ReversePortForwardingListenerCallback(ctx, reqAddr)
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

			chanType = forwardedTCPChannelType
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

func (h forwardedTCPHandler) HandleRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	switch req.Type {
	case OpenSSHStreamLocalForward:
		var (
			reqPayload remoteUnixForwardRequest
			err        error
			addr       string
		)
		if err = gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			return false, []byte{}
		}
		addr = "unix:" + reqPayload.SocketPath
		if srv.ReverseUnixSocketForwardingCallback == nil || !srv.ReverseUnixSocketForwardingCallback(ctx, addr) {
			return false, []byte("unix socket forwarding is disabled")
		}
		return h.handleUnixSocket(conn, ctx, srv, reqPayload.SocketPath)

	case OpenSSHCancelStreamLocalForward:
		var reqPayload remoteUnixForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		if ln, ok := srv.ReverseForwardingRegister.Get(ctx, "unix:"+reqPayload.SocketPath); ok {
			ln.Close()
		}
		return true, nil

	case "tcpip-forward":
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
		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, addr) {
			return false, []byte("port forwarding is disabled")
		}
		return h.handleAddr(conn, ctx, srv, addr)

	case "cancel-tcpip-forward":
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
	default:
		return false, nil
	}
}
