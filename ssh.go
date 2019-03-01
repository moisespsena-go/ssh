package ssh

import (
	"crypto/subtle"
	"net"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

type Signal string

// POSIX signals as listed in RFC 4254 Section 6.10.
const (
	SIGABRT Signal = "ABRT"
	SIGALRM Signal = "ALRM"
	SIGFPE  Signal = "FPE"
	SIGHUP  Signal = "HUP"
	SIGILL  Signal = "ILL"
	SIGINT  Signal = "INT"
	SIGKILL Signal = "KILL"
	SIGPIPE Signal = "PIPE"
	SIGQUIT Signal = "QUIT"
	SIGSEGV Signal = "SEGV"
	SIGTERM Signal = "TERM"
	SIGUSR1 Signal = "USR1"
	SIGUSR2 Signal = "USR2"
)

// DefaultHandler is the default Handler used by Serve.
var DefaultHandler Handler

// Option is a functional option handler for Server.
type Option func(*Server) error

// Handler is a callback for handling established SSH sessions.
type Handler func(Session)

// PublicKeyHandler is a callback for performing public key authentication.
type PublicKeyHandler func(ctx Context, key PublicKey) bool

// PasswordHandler is a callback for performing password authentication.
type PasswordHandler func(ctx Context, password string) bool

// KeyboardInteractiveHandler is a callback for performing keyboard-interactive authentication.
type KeyboardInteractiveHandler func(ctx Context, challenger gossh.KeyboardInteractiveChallenge) bool

// PtyCallback is a hook for allowing PTY sessions.
type PtyCallback func(ctx Context, pty Pty) bool

// SessionRequestCallback is a callback for allowing or denying SSH sessions.
type SessionRequestCallback func(sess Session, requestType string) bool

// ConnCallback is a hook for new connections before handling.
// It allows wrapping for timeouts and limiting by returning
// the net.Conn that will be used as the underlying connection.
type ConnCallback func(conn net.Conn) net.Conn

// LocalPortForwardingCallback is a hook for allowing port forwarding
type LocalPortForwardingCallback func(ctx Context, destinationHost string, destinationPort uint32) bool

// LocalPortForwardingCallback is a hook for allowing port forwarding
type LocalPortForwardingResolverCallback func(ctx Context, destinationHost string, destinationPort uint32) (addr string, err error)

// ReversePortForwardingCallback is a hook for allowing reverse port forwarding
type ReversePortForwardingCallback func(ctx Context, bindHost string, bindPort uint32) bool

// ReversePortForwardingListenerCallback is a hook for create port forwarding listener
type ReversePortForwardingListenerCallback func(ctx Context, bindHost string, bindPort uint32) (net.Listener, error)

// DefaultServerConfigCallback is a hook for creating custom default server configs
type DefaultServerConfigCallback func(ctx Context) *gossh.ServerConfig

// ReversePortForwardingRegister is a port forwarding register
type ReversePortForwardingRegister interface {
	Register(ctx Context, addr string, ln net.Listener)             // Register registry port forwarding listener
	UnRegister(ctx Context, addr string) (ln net.Listener, ok bool) // UnRegister unregister port forwarding listener
	Get(ctx Context, key string) (ln net.Listener, ok bool)         // Get return port forwarding listener
}

type DefaultReversePortForwardingRegister struct {
	forwards map[string]map[string]net.Listener
	mu       sync.Mutex
}

func (r *DefaultReversePortForwardingRegister) Register(ctx Context, addr string, ln net.Listener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.forwards == nil {
		r.forwards = map[string]map[string]net.Listener{}
	}
	clientKey := ctx.RemoteAddr().String()
	_, ok := r.forwards[clientKey]
	if !ok {
		r.forwards[clientKey] = map[string]net.Listener{}
	}
	r.forwards[clientKey][addr] = ln
}

func (r *DefaultReversePortForwardingRegister) UnRegister(ctx Context, addr string) (ln net.Listener, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	clientKey := ctx.RemoteAddr().String()
	_, ok2 := r.forwards[clientKey]
	if !ok2 {
		return
	}
	if ln, ok = r.forwards[clientKey][addr]; ok {
		delete(r.forwards[clientKey], addr)
	}
	if len(r.forwards[clientKey]) == 0 {
		delete(r.forwards, clientKey)
	}
	return
}

func (r *DefaultReversePortForwardingRegister) Get(ctx Context, addr string) (ln net.Listener, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	clientKey := ctx.RemoteAddr().String()
	_, ok2 := r.forwards[clientKey]
	if !ok2 {
		return
	}
	ln, ok = r.forwards[clientKey][addr]
	return
}

// Window represents the size of a PTY window.
type Window struct {
	Width  int
	Height int
}

// Pty represents a PTY request and configuration.
type Pty struct {
	Term   string
	Window Window
	// HELP WANTED: terminal modes!
}

// Serve accepts incoming SSH connections on the listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and
// then calls handler to handle sessions. Handler is typically nil, in which
// case the DefaultHandler is used.
func Serve(l net.Listener, handler Handler, options ...Option) error {
	srv := &Server{Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.Serve(l)
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle sessions on incoming connections. Handler is typically
// nil, in which case the DefaultHandler is used.
func ListenAndServe(addr string, handler Handler, options ...Option) error {
	srv := &Server{Addr: addr, Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.ListenAndServe()
}

// Handle registers the handler as the DefaultHandler.
func Handle(handler Handler) {
	DefaultHandler = handler
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk PublicKey) bool {

	//avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}

type Proxy func(ctx Context, conn *gossh.ServerConn, chans <-chan gossh.NewChannel, reqs <-chan *gossh.Request)

type ProxyCallback func(ctx Context, conn *gossh.ServerConn) (proxy Proxy, ok bool)
