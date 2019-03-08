package ssh

import (
	"io"
	"log"
	"net"
	"os"
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

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
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

func directUnixHandler(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	var d struct {
		SocketPath, Reserved0 string
		Reserved1             uint32
	}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	var addr = "unix:" + d.SocketPath

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, addr) {
		newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	var (
		dest  string
		dconn net.Conn
	)

	if srv.LocalPortForwardingResolverCallback != nil {
		var err error
		if dest, err = srv.LocalPortForwardingResolverCallback(ctx, addr); err != nil {
			newChan.Reject(gossh.ConnectionFailed, "Local forward port resolver failed: "+err.Error())
			return
		}
	} else {
		dest = addr
	}

	var err error

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

		reqIsUnix = strings.HasPrefix(reqAddr, "unix:")
		register  = srv.ReversePortForwardingRegister
	)
	if srv.ReversePortForwardingListenerCallback != nil {
		ln, err = srv.ReversePortForwardingListenerCallback(ctx, reqAddr)
	} else if reqIsUnix {
		pth := strings.TrimPrefix(reqAddr, "unix:")
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
	} else {
		ln, err = net.Listen("tcp", reqAddr)
	}

	if err != nil {
		log.Println("listen failed:", err)
		return false, []byte{}
	}

	addr := ln.Addr().String()

	register.Register(ctx, reqAddr, ln)
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
			if reqIsUnix {
				chanType = forwardedUnixChannelType
				payload = gossh.Marshal(struct{ a, b string }{a: strings.TrimPrefix(reqAddr, "unix:")})
			} else {
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
			}
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

	var payload []byte
	if !reqIsUnix {
		_, destPortStr, _ := net.SplitHostPort(addr)
		destPort, _ := strconv.Atoi(destPortStr)
		payload = gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})
	}
	return true, payload
}

func (h forwardedTCPHandler) HandleRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	switch req.Type {
	case "streamlocal-forward@openssh.com":
		var (
			reqPayload remoteUnixForwardRequest
			err        error
			addr       string
		)
		if err = gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		addr = "unix:" + reqPayload.SocketPath
		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, addr) {
			return false, []byte("port forwarding is disabled")
		}
		return h.handleAddr(conn, ctx, srv, addr)
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
		if ln, ok := srv.ReversePortForwardingRegister.Get(ctx, addr); ok {
			ln.Close()
		}
		return true, nil
	default:
		return false, nil
	}
}
