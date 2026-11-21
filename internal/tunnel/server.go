// Package tunnel is the embedded SSH server devices dial with `ssh -R`
// (ADR-0002, docs/specs/CLIENT_PROTOCOL.md).
//
// Policy, enforced here and nowhere else:
//   - Authentication: public key only. The SSH username is the device ID and
//     the key must equal the one stored at enrolment (constant-time compare).
//     Disabled or unknown devices are refused.
//   - Allowed: "tcpip-forward" for ports that are the device's declared
//     services (the port is the service identity — the server binds its own
//     internal port), "cancel-tcpip-forward", keepalives, and ONE "session"
//     channel running exactly `agent v1 …`.
//   - Refused: shell, pty, X11, agent forwarding, env, subsystems, any other
//     exec, and every "direct-tcpip" (local forward) — a device key can never
//     be used to reach anything on the server side.
//   - One live connection per device: a new login replaces the old one, which
//     heals half-open sessions after NAT/network changes.
package tunnel

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/metrics"
	"github.com/jchirayath/remotehound/internal/model"
)

// Facts are what a device reports in its `agent v1 …` command.
type Facts struct {
	OS            string
	ClientVersion string
	Hostname      string
	Services      []model.Service // kind + remote port only
}

// Hooks is how the tunnel server reads and updates the device registry.
// Implemented by internal/device; faked in tests.
type Hooks interface {
	// Device returns a snapshot of the device or nil.
	Device(id string) *model.Device
	// AllocatePort returns the stable internal port for (device, kind),
	// assigning and persisting one from the range if needed. avoid lists ports
	// that just failed to bind.
	AllocatePort(deviceID, kind string, avoid []int) (int, error)
	// Connected / Disconnected update presence facts (last seen, IP, version).
	Connected(deviceID, remoteIP string, f Facts)
	Disconnected(deviceID string)
	// SessionOpened / SessionClosed record a remote-desktop connection through a
	// tunnel listener. SessionOpened returns a session ID ("" to skip recording,
	// e.g. probes).
	SessionOpened(deviceID, kind, clientAddr string) string
	SessionClosed(sessionID string, bytesIn, bytesOut int64)
	// ClientLog stores the device's piped log tail.
	ClientLog(deviceID string, lines []string)
}

// Config for the server.
type Config struct {
	ListenAddr  string
	BindHost    string // where tunnel listeners bind (internal network)
	HostKeyPath string
	Keepalive   time.Duration // default 30s
	Hooks       Hooks
}

// Server is the tunnel endpoint.
type Server struct {
	cfg     Config
	sshCfg  *ssh.ServerConfig
	hostKey ssh.Signer
	ln      net.Listener

	mu    sync.RWMutex
	conns map[string]*deviceConn // deviceID -> live connection

	perIP   sync.Map // ip -> *int64 concurrent unauthenticated handshakes
	preauth atomic.Int64
}

// New loads or creates the host key and prepares the server.
func New(cfg Config) (*Server, error) {
	if cfg.Keepalive == 0 {
		cfg.Keepalive = 30 * time.Second
	}
	signer, err := loadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, hostKey: signer, conns: map[string]*deviceConn{}}
	s.sshCfg = &ssh.ServerConfig{
		ServerVersion:     "SSH-2.0-RemoteHound",
		MaxAuthTries:      2,
		PublicKeyCallback: s.authenticate,
		// No password, keyboard-interactive or none auth: unset callbacks are refused.
	}
	s.sshCfg.AddHostKey(signer)
	return s, nil
}

// HostKey returns the public host key (pinned by bootstrap scripts).
func (s *Server) HostKey() ssh.PublicKey { return s.hostKey.PublicKey() }

// KnownHostsLine renders the line a client pins for host:port.
func (s *Server) KnownHostsLine(host string, port int) string {
	h := host
	if port != 22 {
		h = "[" + host + "]:" + strconv.Itoa(port)
	}
	return h + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.hostKey.PublicKey())))
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- fixed path under the data dir
		return ssh.ParsePrivateKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "remotehound host key")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

func (s *Server) authenticate(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	id := meta.User()
	d := s.cfg.Hooks.Device(id)
	fail := func(reason string) (*ssh.Permissions, error) {
		metrics.Default.Inc("remotehound_tunnel_auth_total", "Tunnel authentication attempts.", "outcome", "denied")
		logx.L().Warn("Tunnel login refused", logx.Event("tunnel.auth"), slog.String("app.outcome", "denied"),
			slog.String("app.reason", reason), slog.String("app.device.id", safeID(id)), slog.String("client.address", hostOnly(meta.RemoteAddr())))
		return nil, errors.New("denied")
	}
	if d == nil {
		return fail("unknown device")
	}
	if d.Status != model.DeviceActive {
		return fail("device " + d.Status)
	}
	stored, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.PublicKey))
	if err != nil {
		return fail("stored key unreadable")
	}
	if subtle.ConstantTimeCompare(stored.Marshal(), key.Marshal()) != 1 {
		return fail("key mismatch")
	}
	metrics.Default.Inc("remotehound_tunnel_auth_total", "Tunnel authentication attempts.", "outcome", "success")
	return &ssh.Permissions{Extensions: map[string]string{"device_id": d.ID}}, nil
}

var idRe = regexp.MustCompile(`^dev_[a-z0-9]{6,40}$`)

func safeID(s string) string {
	if idRe.MatchString(s) {
		return s
	}
	return "invalid"
}

func hostOnly(a net.Addr) string {
	if a == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

// Serve accepts device connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("ssh listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.ln = ln
	logx.L().Info("Tunnel SSH server listening", logx.Event("tunnel.listen"), slog.String("server.address", ln.Addr().String()))
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.closeAll()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handshake(ctx, c)
	}
}

// Addr returns the bound listener address (useful when ListenAddr used :0).
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

const (
	maxHandshakesPerIP = 8
	maxHandshakesTotal = 256
)

func (s *Server) handshake(ctx context.Context, c net.Conn) {
	ip := hostOnly(c.RemoteAddr())
	if s.preauth.Add(1) > maxHandshakesTotal {
		s.preauth.Add(-1)
		c.Close()
		return
	}
	cnt, _ := s.perIP.LoadOrStore(ip, new(int64))
	n := cnt.(*int64)
	release := func() {
		s.preauth.Add(-1)
		if atomic.AddInt64(n, -1) <= 0 {
			s.perIP.Delete(ip) // bounded map: no entry outlives its handshakes
		}
	}
	if atomic.AddInt64(n, 1) > maxHandshakesPerIP {
		release()
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second)) // pre-auth budget
	sconn, chans, reqs, err := ssh.NewServerConn(c, s.sshCfg)
	release()
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	id := sconn.Permissions.Extensions["device_id"]
	dc := &deviceConn{
		srv: s, id: id, conn: sconn, remoteIP: ip,
		since:     time.Now(),
		forwards:  map[int]*forward{},
		done:      make(chan struct{}),
		lastAlive: time.Now(),
	}
	s.replace(dc)
	dc.run(ctx, chans, reqs)
}

// replace registers dc and closes any previous connection for the device.
func (s *Server) replace(dc *deviceConn) {
	s.mu.Lock()
	old := s.conns[dc.id]
	s.conns[dc.id] = dc
	s.mu.Unlock()
	if old != nil {
		logx.L().Info("Replacing previous tunnel for device", logx.Event("tunnel.replace"), slog.String("app.device.id", dc.id))
		old.close("replaced")
	}
}

func (s *Server) remove(dc *deviceConn) {
	s.mu.Lock()
	if s.conns[dc.id] == dc {
		delete(s.conns, dc.id)
	}
	s.mu.Unlock()
}

func (s *Server) closeAll() {
	s.mu.RLock()
	all := make([]*deviceConn, 0, len(s.conns))
	for _, dc := range s.conns {
		all = append(all, dc)
	}
	s.mu.RUnlock()
	for _, dc := range all {
		dc.close("shutdown")
	}
}

// Online reports whether a device has a live tunnel.
func (s *Server) Online(deviceID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.conns[deviceID]
	return ok
}

// Forwarded returns the remote ports the device is currently forwarding.
func (s *Server) Forwarded(deviceID string) map[int]int {
	s.mu.RLock()
	dc := s.conns[deviceID]
	s.mu.RUnlock()
	if dc == nil {
		return nil
	}
	return dc.forwardMap()
}

// ConnectedSince returns when the live tunnel started (zero if offline).
func (s *Server) ConnectedSince(deviceID string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if dc := s.conns[deviceID]; dc != nil {
		return dc.since
	}
	return time.Time{}
}

// OnlineCount returns the number of live tunnels.
func (s *Server) OnlineCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.conns)
}

// Kick sends a control line ("reconnect" or "revoked") then closes the tunnel.
func (s *Server) Kick(deviceID, control string) bool {
	s.mu.RLock()
	dc := s.conns[deviceID]
	s.mu.RUnlock()
	if dc == nil {
		return false
	}
	// The control write can block if the client stops reading (zero window);
	// close unconditionally after 500 ms regardless.
	go dc.control(control)
	time.AfterFunc(500*time.Millisecond, func() { dc.close(control) })
	return true
}

// TerminateSession closes one proxied connection by session ID.
func (s *Server) TerminateSession(sessionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, dc := range s.conns {
		if dc.terminate(sessionID) {
			return true
		}
	}
	return false
}

// Info describes a live tunnel for the Debug screen.
type Info struct {
	DeviceID        string        `json:"device_id"`
	RemoteAddress   string        `json:"remote_address"`
	ConnectedSince  time.Time     `json:"connected_since"`
	ClientVersion   string        `json:"client_version"`
	LastKeepaliveAt time.Time     `json:"last_keepalive_at"`
	Forwards        []ForwardInfo `json:"forwards"`
}

// ForwardInfo describes one bound forward.
type ForwardInfo struct {
	Kind         string `json:"kind"`
	RemotePort   int    `json:"remote_port"`
	InternalPort int    `json:"internal_port"`
	ActiveConns  int64  `json:"active_conns"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
}

// Infos lists live tunnels sorted by device ID.
func (s *Server) Infos() []Info {
	s.mu.RLock()
	all := make([]*deviceConn, 0, len(s.conns))
	for _, dc := range s.conns {
		all = append(all, dc)
	}
	s.mu.RUnlock()
	out := make([]Info, 0, len(all))
	for _, dc := range all {
		out = append(out, dc.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// ---- per-device connection ---------------------------------------------------

type deviceConn struct {
	srv      *Server
	id       string
	conn     *ssh.ServerConn
	remoteIP string
	since    time.Time
	version  string

	mu        sync.Mutex
	forwards  map[int]*forward // remote port -> forward
	session   ssh.Channel
	sessions  int  // session channels accepted (max 1)
	execDone  bool // the one agent command has run
	lastAlive time.Time
	closed    bool
	done      chan struct{}
}

type forward struct {
	kind         string
	bindAddr     string // the address string the client asked for (echoed back in channel opens)
	remotePort   int
	internalPort int
	ln           net.Listener
	active       atomic.Int64
	bytesIn      atomic.Int64
	bytesOut     atomic.Int64
	connMu       sync.Mutex
	conns        map[string]net.Conn // sessionID -> conn
}

func (dc *deviceConn) log() *slog.Logger { return logx.L().With(slog.String("app.device.id", dc.id)) }

func (dc *deviceConn) scopeCtx(ctx context.Context) context.Context {
	d := dc.srv.cfg.Hooks.Device(dc.id)
	return logx.WithScope(ctx, logx.Scope{DeviceID: dc.id, Debug: d != nil && d.Debug})
}

func (dc *deviceConn) run(parent context.Context, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	ctx, cancel := context.WithCancel(dc.scopeCtx(parent))
	defer cancel()
	metrics.Default.Inc("remotehound_tunnel_connections_total", "Tunnel connections accepted.")
	dc.log().InfoContext(ctx, "Tunnel connected", logx.Event("tunnel.open"), slog.String("client.address", dc.remoteIP),
		slog.String("app.client_version", string(dc.conn.ClientVersion())))

	go dc.keepalive(ctx)
	go func() {
		for nc := range chans {
			dc.handleChannel(ctx, nc)
		}
	}()
	for req := range reqs {
		dc.handleGlobal(ctx, req)
	}
	// reqs closes when the connection ends.
	dc.close("disconnected")
}

func (dc *deviceConn) close(reason string) {
	dc.mu.Lock()
	if dc.closed {
		dc.mu.Unlock()
		return
	}
	dc.closed = true
	fwds := make([]*forward, 0, len(dc.forwards))
	for _, f := range dc.forwards {
		fwds = append(fwds, f)
	}
	dc.mu.Unlock()
	close(dc.done)
	for _, f := range fwds {
		f.ln.Close()
		f.closeConns()
	}
	dc.conn.Close()
	wasCurrent := false
	dc.srv.mu.RLock()
	wasCurrent = dc.srv.conns[dc.id] == dc
	dc.srv.mu.RUnlock()
	dc.srv.remove(dc)
	if wasCurrent {
		dc.srv.cfg.Hooks.Disconnected(dc.id)
	}
	dc.log().Info("Tunnel closed", logx.Event("tunnel.close"), slog.String("app.reason", reason),
		slog.Int64("app.duration_ms", time.Since(dc.since).Milliseconds()))
}

func (dc *deviceConn) keepalive(ctx context.Context) {
	t := time.NewTicker(dc.srv.cfg.Keepalive)
	defer t.Stop()
	misses := 0
	pings := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-dc.done:
			return
		case <-t.C:
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := dc.conn.SendRequest("keepalive@openssh.com", true, nil)
			res <- err
		}()
		select {
		case err := <-res:
			// OpenSSH answers keepalive@openssh.com with a failure reply; any reply proves liveness.
			if err != nil {
				misses++
			} else {
				misses = 0
				dc.mu.Lock()
				dc.lastAlive = time.Now()
				dc.mu.Unlock()
			}
		case <-time.After(15 * time.Second):
			misses++
		}
		if misses >= 3 {
			dc.log().Warn("Tunnel keepalive lost; closing", logx.Event("tunnel.keepalive_lost"))
			dc.close("keepalive lost")
			return
		}
		pings++
		if pings%2 == 0 {
			go dc.control("ping") // never let a non-reading client stall keepalive
		}
	}
}

func (dc *deviceConn) control(line string) {
	dc.mu.Lock()
	ch := dc.session
	dc.mu.Unlock()
	if ch != nil {
		_, _ = io.WriteString(ch, line+"\n")
	}
}

type tcpipForwardMsg struct {
	Addr string
	Port uint32
}

func (dc *deviceConn) handleGlobal(ctx context.Context, req *ssh.Request) {
	switch req.Type {
	case "tcpip-forward":
		var m tcpipForwardMsg
		if err := ssh.Unmarshal(req.Payload, &m); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		if err := dc.bind(ctx, m); err != nil {
			dc.log().WarnContext(ctx, "Forward refused", logx.Event("tunnel.forward"), slog.String("app.outcome", "denied"),
				slog.Int("app.remote_port", int(m.Port)), slog.String("app.reason", err.Error()))
			_ = req.Reply(false, nil)
			return
		}
		var reply []byte
		if m.Port == 0 {
			reply = ssh.Marshal(struct{ Port uint32 }{m.Port})
		}
		_ = req.Reply(true, reply)
	case "cancel-tcpip-forward":
		var m tcpipForwardMsg
		if ssh.Unmarshal(req.Payload, &m) == nil {
			dc.unbind(int(m.Port))
		}
		_ = req.Reply(true, nil)
	case "keepalive@openssh.com":
		_ = req.Reply(true, nil)
	default:
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func (dc *deviceConn) bind(ctx context.Context, m tcpipForwardMsg) error {
	d := dc.srv.cfg.Hooks.Device(dc.id)
	if d == nil || d.Status != model.DeviceActive {
		return errors.New("device not active")
	}
	svc := d.ServiceByRemotePort(int(m.Port))
	if svc == nil {
		return fmt.Errorf("port %d is not a declared service", m.Port)
	}
	dc.mu.Lock()
	if _, dup := dc.forwards[int(m.Port)]; dup {
		dc.mu.Unlock()
		return errors.New("already forwarded")
	}
	dc.mu.Unlock()

	var ln net.Listener
	var port int
	var avoid []int
	for attempt := 0; attempt < 5; attempt++ {
		p, err := dc.srv.cfg.Hooks.AllocatePort(dc.id, svc.Kind, avoid)
		if err != nil {
			return err
		}
		l, err := net.Listen("tcp", net.JoinHostPort(dc.srv.cfg.BindHost, strconv.Itoa(p)))
		if err == nil {
			ln, port = l, p
			break
		}
		avoid = append(avoid, p)
		dc.log().WarnContext(ctx, "Tunnel port busy; reallocating", logx.Event("tunnel.port_busy"), slog.Int("app.internal_port", p))
	}
	if ln == nil {
		return errors.New("no free tunnel port")
	}
	f := &forward{kind: svc.Kind, bindAddr: m.Addr, remotePort: int(m.Port), internalPort: port, ln: ln, conns: map[string]net.Conn{}}
	dc.mu.Lock()
	if dc.closed {
		dc.mu.Unlock()
		ln.Close()
		return errors.New("connection closed")
	}
	dc.forwards[int(m.Port)] = f
	dc.mu.Unlock()
	go dc.acceptLoop(ctx, f)
	dc.log().InfoContext(ctx, "Forward bound", logx.Event("tunnel.forward"), slog.String("app.outcome", "success"),
		slog.String("app.service", svc.Kind), slog.Int("app.remote_port", int(m.Port)), slog.Int("app.internal_port", port))
	return nil
}

func (dc *deviceConn) unbind(port int) {
	dc.mu.Lock()
	f := dc.forwards[port]
	delete(dc.forwards, port)
	dc.mu.Unlock()
	if f != nil {
		f.ln.Close()
	}
}

func (dc *deviceConn) forwardMap() map[int]int {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	m := make(map[int]int, len(dc.forwards))
	for rp, f := range dc.forwards {
		m[rp] = f.internalPort
	}
	return m
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func (dc *deviceConn) acceptLoop(ctx context.Context, f *forward) {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go dc.proxy(ctx, f, c)
	}
}

func (dc *deviceConn) proxy(ctx context.Context, f *forward, c net.Conn) {
	defer c.Close()
	originHost, originPortS, _ := net.SplitHostPort(c.RemoteAddr().String())
	originPort, _ := strconv.Atoi(originPortS)
	payload := ssh.Marshal(forwardedTCPPayload{Addr: f.bindAddr, Port: uint32(f.remotePort), OriginAddr: originHost, OriginPort: uint32(originPort)})
	ch, reqs, err := dc.conn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		dc.log().WarnContext(ctx, "Device refused forwarded connection", logx.Event("tunnel.channel"), logx.Err(err), slog.String("app.service", f.kind))
		return
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	sid := dc.srv.cfg.Hooks.SessionOpened(dc.id, f.kind, originHost)
	if sid != "" {
		f.connMu.Lock()
		f.conns[sid] = c
		f.connMu.Unlock()
	}
	f.active.Add(1)
	metrics.Default.Inc("remotehound_tunnel_streams_total", "Connections proxied through tunnels.", "service", f.kind)

	var in, out int64
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(ch, c); out = n; _ = ch.CloseWrite(); done <- struct{}{} }()
	go func() {
		n, _ := io.Copy(c, ch)
		in = n
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	f.active.Add(-1)
	f.bytesIn.Add(in)
	f.bytesOut.Add(out)
	metrics.Default.Add("remotehound_tunnel_bytes_total", "Bytes proxied through tunnels.", float64(in+out), "service", f.kind)
	if sid != "" {
		f.connMu.Lock()
		delete(f.conns, sid)
		f.connMu.Unlock()
		dc.srv.cfg.Hooks.SessionClosed(sid, in, out)
	}
}

func (f *forward) closeConns() {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	for _, c := range f.conns {
		c.Close()
	}
}

func (dc *deviceConn) terminate(sessionID string) bool {
	dc.mu.Lock()
	fwds := make([]*forward, 0, len(dc.forwards))
	for _, f := range dc.forwards {
		fwds = append(fwds, f)
	}
	dc.mu.Unlock()
	for _, f := range fwds {
		f.connMu.Lock()
		c := f.conns[sessionID]
		f.connMu.Unlock()
		if c != nil {
			c.Close()
			return true
		}
	}
	return false
}

func (dc *deviceConn) info() Info {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	in := Info{DeviceID: dc.id, RemoteAddress: dc.remoteIP, ConnectedSince: dc.since, ClientVersion: dc.version, LastKeepaliveAt: dc.lastAlive}
	for _, f := range dc.forwards {
		in.Forwards = append(in.Forwards, ForwardInfo{Kind: f.kind, RemotePort: f.remotePort, InternalPort: f.internalPort,
			ActiveConns: f.active.Load(), BytesIn: f.bytesIn.Load(), BytesOut: f.bytesOut.Load()})
	}
	sort.Slice(in.Forwards, func(i, j int) bool { return in.Forwards[i].RemotePort < in.Forwards[j].RemotePort })
	return in
}

// ---- the session channel: `agent v1 …` ----------------------------------------

func (dc *deviceConn) handleChannel(ctx context.Context, nc ssh.NewChannel) {
	if nc.ChannelType() != "session" {
		_ = nc.Reject(ssh.Prohibited, "only remote forwards are allowed")
		return
	}
	dc.mu.Lock()
	busy := dc.sessions > 0
	if !busy {
		dc.sessions++
	}
	dc.mu.Unlock()
	if busy {
		_ = nc.Reject(ssh.Prohibited, "one session per tunnel")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go dc.sessionRequests(ctx, ch, reqs)
}

func (dc *deviceConn) sessionRequests(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			// shell, pty-req, x11-req, env, subsystem, auth-agent-req@openssh.com …
			_ = req.Reply(false, nil)
			continue
		}
		var m struct{ Command string }
		if ssh.Unmarshal(req.Payload, &m) != nil {
			_ = req.Reply(false, nil)
			continue
		}
		dc.mu.Lock()
		again := dc.execDone
		dc.execDone = true
		dc.mu.Unlock()
		if again { // one agent command per tunnel: no presence-write amplification
			_ = req.Reply(false, nil)
			continue
		}
		facts, err := ParseAgentCommand(m.Command)
		if err != nil {
			_ = req.Reply(false, nil)
			dc.log().WarnContext(ctx, "Refused exec", logx.Event("tunnel.exec"), slog.String("app.outcome", "denied"), slog.String("app.reason", err.Error()))
			continue
		}
		_ = req.Reply(true, nil)
		dc.mu.Lock()
		dc.session = ch
		dc.version = facts.ClientVersion
		dc.mu.Unlock()
		dc.srv.cfg.Hooks.Connected(dc.id, dc.remoteIP, facts)
		_, _ = io.WriteString(ch, "ok "+dc.id+"\n")
		go dc.readClientLog(ch)
	}
}

func (dc *deviceConn) readClientLog(ch ssh.Channel) {
	sc := bufio.NewScanner(io.LimitReader(ch, 256*1024))
	sc.Buffer(make([]byte, 4096), 4096)
	var lines []string
	for sc.Scan() && len(lines) < 200 {
		line := sc.Text()
		if len(line) > 500 {
			line = line[:500]
		}
		lines = append(lines, line)
	}
	if len(lines) > 0 {
		dc.srv.cfg.Hooks.ClientLog(dc.id, lines)
	}
}

// ParseAgentCommand validates `agent v1 key=value …` and extracts facts.
// Unknown keys are ignored (forward-compatible); values are length- and
// charset-limited.
func ParseAgentCommand(cmd string) (Facts, error) {
	var f Facts
	fields := strings.Fields(cmd)
	if len(fields) < 2 || fields[0] != "agent" || fields[1] != "v1" {
		return f, errors.New("not an agent v1 command")
	}
	if len(cmd) > 1024 {
		return f, errors.New("command too long")
	}
	for _, kv := range fields[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !factRe.MatchString(v) {
			continue
		}
		switch k {
		case "os":
			switch v {
			case "linux", "macos", "windows":
				f.OS = v
			}
		case "ver":
			f.ClientVersion = v
		case "host":
			f.Hostname = v
		case "services":
			for _, sp := range strings.Split(v, ",") {
				kind, portS, ok := strings.Cut(sp, ":")
				port, err := strconv.Atoi(portS)
				if !ok || err != nil || port < 1 || port > 65535 {
					continue
				}
				if _, known := model.DefaultRemotePort[kind]; known {
					f.Services = append(f.Services, model.Service{Kind: kind, RemotePort: port})
				}
			}
		}
	}
	return f, nil
}

var factRe = regexp.MustCompile(`^[A-Za-z0-9._:,-]{1,128}$`)
