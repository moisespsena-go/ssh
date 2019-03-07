package ssh

import (
	"io"
	"log"
	"net"
	"strconv"

	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedTCPChannelType = "forwarded-tcpip"
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

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	var dest string

	if srv.LocalPortForwardingResolverCallback != nil {
		var err error
		if dest, err = srv.LocalPortForwardingResolverCallback(ctx, d.DestAddr, d.DestPort); err != nil {
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

type forwardedTCPHandler struct {
}

func (h forwardedTCPHandler) HandleRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	register := srv.ReversePortForwardingRegister
	switch req.Type {
	case "tcpip-forward":
		var (
			reqPayload remoteForwardRequest
			err        error
		)
		if err = gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
			return false, []byte("port forwarding is disabled")
		}
		var (
			reqAddr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
			ln      net.Listener
		)
		if srv.ReversePortForwardingListenerCallback != nil {
			ln, err = srv.ReversePortForwardingListenerCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort)
		} else {
			ln, err = net.Listen("tcp", reqAddr)
		}

		if err != nil {
			// TODO: log listen failure
			return false, []byte{}
		}

		addr := ln.Addr().String()

		_, destPortStr, _ := net.SplitHostPort(addr)
		destPort, _ := strconv.Atoi(destPortStr)
		register.Register(ctx, addr, ln)
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
				originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.Atoi(orignPortStr)
				payload := gossh.Marshal(&remoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   uint32(destPort),
					OriginAddr: originAddr,
					OriginPort: uint32(originPort),
				})
				go func() {
					ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
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
		return true, gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})

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
