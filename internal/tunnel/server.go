// Package tunnel is the embedded SSH server devices dial with `ssh -R`
// (ADR-0002, docs/specs/CLIENT_PROTOCOL.md).
//
// Policy, enforced here and nowhere else:
//   - Authentication: public key only. The SSH username is the device ID and
//     the key must equal the one stored at enrollment (constant-time compare).
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
//
// Script-free enrollment (ADR-0005), enforced here too:
//   - A username that is an enrollment code logs in through the Enroller (the
//     same wrong-code limiter as HTTP): attended codes with "none" only,
//     persistent codes with an ed25519 "publickey" only. "none" is refused for
//     every other username.
//   - A code login is no device until it sends `hello v1 …` (or a bare shell
//     request) within helloTimeout; every global request is held
//     (at most maxHeldForwards) and answered in order once the device exists.
//   - Manual devices (ssh-manual, ssh-attended) may run `hello v1 …` or ask for
//     a shell (answered as hello, no shell runs) — never `agent v1`; script
//     devices the reverse. Attended devices never log in again.
//   - A manual device's -R for a conventional port (22, 3389, 5900) it has not
//     declared yet is declared, then bound (the typed equivalent of the
//     watchdog's services= fact). Any other undeclared port is refused.
package tunnel

import (
	"bufio"
	"container/list"
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
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/core/ids"
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
	// AddService declares a conventional service (kind at its default port)
	// on a typed device that forwards it before the registry has it — the
	// typed equivalent of the watchdog's services= fact (ADR-0005).
	AddService(deviceID, kind string, remotePort int) error
}

// Enroller lets a person enroll by typing an ssh command whose username is an
// enrollment code (ADR-0005). Implemented by internal/enroll; faked in tests.
type Enroller interface {
	// CodeLogin checks code for a login from ip without consuming it. A wrong
	// code counts against the shared wrong-code limiter; false also when the
	// code is used, expired or the caller is throttled.
	CodeLogin(code, ip string) (CodeInfo, bool)
	// RedeemSSH consumes the code and creates the device. The error's message
	// is shown to the person in their terminal.
	RedeemSSH(enrollmentID string, r SSHEnrollment) (Redeemed, error)
}

// CodeInfo is an open enrollment code as a login sees it.
type CodeInfo struct {
	EnrollmentID string
	Mode         string // model.EnrollModeAttended | model.EnrollModePersistent
}

// SSHEnrollment is what a code login reported before the device exists.
type SSHEnrollment struct {
	IP        string
	Banner    string // the client's SSH version string
	PublicKey string // authorized_keys line (persistent codes); "" for attended
	Facts     Facts  // from hello, with Services taken from the held -R requests
}

// Redeemed is the device a code login created.
type Redeemed struct {
	DeviceID, DeviceName string
	// Reconnect is the command for the next login without a code ("" for attended).
	Reconnect string
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
	ln      atomic.Pointer[net.Listener] // set by Serve, read by Addr from other goroutines

	mu    sync.RWMutex
	conns map[string]*deviceConn // deviceID -> live connection

	pending        *pending      // unauthenticated handshakes
	preauthTimeout time.Duration // pre-auth budget (tests shorten it)
	helloTimeout   time.Duration // a code login's budget to send hello (tests shorten it)
	enroller       atomic.Pointer[enrollerBox]

	codeMu     sync.Mutex
	codeLogins map[string]int // enrollment ID -> code logins waiting for hello
	codeTotal  int
	codeChecks map[string]int // remote addr -> code lookups during its handshake
}

type enrollerBox struct{ e Enroller }

// SetEnroller enables code logins (ADR-0005). Without one they are refused.
// A nil Enroller is ignored: once enabled, code logins stay enabled.
func (s *Server) SetEnroller(e Enroller) {
	if e != nil {
		s.enroller.Store(&enrollerBox{e})
	}
}

func (s *Server) getEnroller() Enroller {
	if b := s.enroller.Load(); b != nil {
		return b.e
	}
	return nil
}

const (
	helloTimeout    = 10 * time.Second
	maxHeldForwards = 8
)

// New loads or creates the host key and prepares the server.
func New(cfg Config) (*Server, error) {
	if cfg.Keepalive == 0 {
		cfg.Keepalive = 30 * time.Second
	}
	signer, err := loadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, hostKey: signer, conns: map[string]*deviceConn{},
		pending: newPending(maxHandshakesPerClient, maxHandshakesPerIPv6Net, maxHandshakesTotal), preauthTimeout: preauthTimeout,
		helloTimeout: helloTimeout, codeLogins: map[string]int{}, codeChecks: map[string]int{}}
	s.sshCfg = &ssh.ServerConfig{
		// No SHA-1 key exchange or MAC. Every client the bootstrap supports
		// (OpenSSH ≥ 7.4, incl. Windows 10's 7.7) offers curve25519-sha256 and
		// AES-GCM / chacha20 / hmac-sha2-*-etm. Ciphers stay at the x/crypto
		// defaults (no CBC/RC4); strict-kex is added by x/crypto regardless.
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519, ssh.KeyExchangeECDHP256,
				ssh.KeyExchangeECDHP384, ssh.KeyExchangeECDHP521, ssh.KeyExchangeDH14SHA256},
			MACs: []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM, ssh.HMACSHA256, ssh.HMACSHA512},
		},
		ServerVersion:     "SSH-2.0-RemoteHound",
		MaxAuthTries:      2,
		PublicKeyCallback: s.authenticate,
		// "none" only for attended enrollment codes (authNone refuses the rest).
		// No password or keyboard-interactive: unset callbacks are refused.
		NoClientAuth:         true,
		NoClientAuthCallback: s.authNone,
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

func authFail(meta ssh.ConnMetadata, reason string) (*ssh.Permissions, error) {
	metrics.Default.Inc("remotehound_tunnel_auth_total", "Tunnel authentication attempts.", "outcome", "denied")
	logx.L().Warn("Tunnel login refused", logx.Event("tunnel.auth"), slog.String("app.outcome", "denied"),
		slog.String("app.reason", reason), slog.String("app.device.id", safeID(meta.User())), slog.String("client.address", hostOnly(meta.RemoteAddr())))
	return nil, errors.New("denied")
}

// codeUser returns the enrollment code a username spells, or "".
func codeUser(user string) string {
	c := strings.ToLower(user)
	if ids.ValidCode(c) {
		return c
	}
	return ""
}

// errNotNone is the quiet refusal of "none": OpenSSH tries it before every
// key login, so refusing it is routine, not an event.
var errNotNone = errors.New("none not allowed")

// authNone admits an attended enrollment code with the "none" method, and
// nothing else.
func (s *Server) authNone(meta ssh.ConnMetadata) (*ssh.Permissions, error) {
	code := codeUser(meta.User())
	e := s.getEnroller()
	if code == "" || e == nil {
		return nil, errNotNone
	}
	if !s.allowCodeCheck(meta) {
		return authFail(meta, "too many code checks on one connection")
	}
	ci, ok := e.CodeLogin(code, hostOnly(meta.RemoteAddr()))
	if !ok {
		return authFail(meta, "enrollment code refused")
	}
	if ci.Mode != model.EnrollModeAttended {
		return nil, errNotNone // a persistent code needs a key: the client tries publickey next
	}
	metrics.Default.Inc("remotehound_tunnel_auth_total", "Tunnel authentication attempts.", "outcome", "enrol_attended")
	return &ssh.Permissions{Extensions: map[string]string{"enrollment_id": ci.EnrollmentID}}, nil
}

// authCodeKey admits a persistent enrollment code with an ed25519 key. x/crypto
// verifies the signature before the login succeeds, so the key bound later is
// one the client holds.
func (s *Server) authCodeKey(meta ssh.ConnMetadata, code string, key ssh.PublicKey) (*ssh.Permissions, error) {
	e := s.getEnroller()
	if e == nil {
		return authFail(meta, "code logins disabled")
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return authFail(meta, "enrollment key is not ed25519")
	}
	if !s.allowCodeCheck(meta) {
		return authFail(meta, "too many code checks on one connection")
	}
	ci, ok := e.CodeLogin(code, hostOnly(meta.RemoteAddr()))
	if !ok {
		return authFail(meta, "enrollment code refused")
	}
	if ci.Mode != model.EnrollModePersistent {
		return authFail(meta, "attended code offered a key")
	}
	metrics.Default.Inc("remotehound_tunnel_auth_total", "Tunnel authentication attempts.", "outcome", "enrol_key")
	return &ssh.Permissions{Extensions: map[string]string{"enrollment_id": ci.EnrollmentID,
		"public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}}, nil
}

func (s *Server) authenticate(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	id := meta.User()
	if code := codeUser(id); code != "" {
		return s.authCodeKey(meta, code, key)
	}
	d := s.cfg.Hooks.Device(id)
	fail := func(reason string) (*ssh.Permissions, error) { return authFail(meta, reason) }
	if d == nil {
		return fail("unknown device")
	}
	if d.Status != model.DeviceActive {
		return fail("device " + d.Status)
	}
	if d.Transport == model.TransportAttended {
		return fail("attended device: one session only")
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

// Serve accepts device connections until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("ssh listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.ln.Store(&ln)
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
	ln := s.ln.Load()
	if ln == nil {
		return nil
	}
	return (*ln).Addr()
}

// Pre-auth limits. A client is ids.ClientKey (IPv4 address, IPv6 /64); an
// IPv6 /48 (ids.ClientNetKey) is capped too, so rotating /64s inside one site
// allocation does not multiply the budget. A real device finishes its
// handshake in well under a second, so a short budget plus "evict from the
// busiest client" when full means a flood of slow handshakes delays devices by
// at most a retry instead of locking them out: a client holding one pending
// handshake is evicted only once every pending client holds just one.
const (
	maxHandshakesPerClient  = 8
	maxHandshakesPerIPv6Net = 64
	maxHandshakesTotal      = 1024
	preauthTimeout          = 5 * time.Second
)

// pending tracks unauthenticated handshakes per client, oldest first.
type pending struct {
	mu        sync.Mutex
	perClient int
	perNet    int
	total     int
	n         int
	seq       uint64
	byClient  map[string]int // pending per client key (mirrors len(lists[key]))
	byNet     map[string]int // pending per IPv6 /48
	lists     map[string]*list.List
}

type pendingConn struct {
	c        net.Conn
	key, net string
	seq      uint64
	el       *list.Element // nil once released or evicted
}

func newPending(perClient, perNet, total int) *pending {
	return &pending{perClient: perClient, perNet: perNet, total: total,
		byClient: map[string]int{}, byNet: map[string]int{}, lists: map[string]*list.List{}}
}

// admit registers a handshake from ip. It refuses when that client (or its
// IPv6 /48) is at its cap; when the table is full it closes the oldest pending
// handshake of the client holding the most (ties: the oldest overall) instead
// of refusing the new one.
func (p *pending) admit(ip string, c net.Conn) (*pendingConn, bool) {
	key, nk := ids.ClientKey(ip), ids.ClientNetKey(ip)
	p.mu.Lock()
	if p.byClient[key] >= p.perClient || (nk != "" && p.byNet[nk] >= p.perNet) {
		p.mu.Unlock()
		metrics.Default.Inc("remotehound_tunnel_preauth_refused_total", "Unauthenticated SSH handshakes refused at the per-client or per-/48 cap.")
		return nil, false
	}
	var evicted net.Conn
	if p.n >= p.total {
		var victim *pendingConn
		for _, l := range p.lists {
			old := l.Front().Value.(*pendingConn)
			if victim == nil || l.Len() > p.byClient[victim.key] || (l.Len() == p.byClient[victim.key] && old.seq < victim.seq) {
				victim = old
			}
		}
		p.removeLocked(victim)
		evicted = victim.c
	}
	p.seq++
	pc := &pendingConn{c: c, key: key, net: nk, seq: p.seq}
	l := p.lists[key]
	if l == nil {
		l = list.New()
		p.lists[key] = l
	}
	pc.el = l.PushBack(pc)
	p.byClient[key]++
	if nk != "" {
		p.byNet[nk]++
	}
	p.n++
	p.mu.Unlock()
	if evicted != nil {
		metrics.Default.Inc("remotehound_tunnel_preauth_evicted_total", "Unauthenticated SSH handshakes closed to make room when the table was full.")
		evicted.Close() // its NewServerConn fails, and done reports the eviction
	}
	return pc, true
}

// done releases pc and reports whether it still owned its slot: false means
// it was evicted (its conn is closed) and the handshake must be abandoned even
// if it completed. Idempotent.
func (p *pending) done(pc *pendingConn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pc.el == nil {
		return false
	}
	p.removeLocked(pc)
	return true
}

// removeLocked drops pc; maps lose a key with its last handshake (bounded).
func (p *pending) removeLocked(pc *pendingConn) {
	l := p.lists[pc.key]
	l.Remove(pc.el)
	pc.el = nil
	p.n--
	if l.Len() == 0 {
		delete(p.lists, pc.key)
	}
	if p.byClient[pc.key]--; p.byClient[pc.key] <= 0 {
		delete(p.byClient, pc.key)
	}
	if pc.net != "" {
		if p.byNet[pc.net]--; p.byNet[pc.net] <= 0 {
			delete(p.byNet, pc.net)
		}
	}
}

func (p *pending) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

func (s *Server) handshake(ctx context.Context, c net.Conn) {
	ip := hostOnly(c.RemoteAddr())
	pc, ok := s.pending.admit(ip, c)
	if !ok {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Now().Add(s.preauthTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(c, s.sshCfg)
	s.forgetCodeChecks(c.RemoteAddr().String())
	owned := s.pending.done(pc)
	if err == nil && !owned {
		// Evicted just as authentication completed: the conn is already closed,
		// so finish cleanly rather than register a dead tunnel.
		sconn.Close()
		err = net.ErrClosed
	}
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	ext := sconn.Permissions.Extensions
	dc := &deviceConn{
		srv: s, id: ext["device_id"], conn: sconn, remoteIP: ip,
		since:     time.Now(),
		forwards:  map[int]*forward{},
		done:      make(chan struct{}),
		lastAlive: time.Now(),
	}
	if enr := ext["enrollment_id"]; enr != "" {
		// A code login: no device, not registered, until hello (ADR-0005).
		if !s.acquireCodeLogin(enr) {
			logx.L().Warn("Too many logins with one enrollment code", logx.Event("tunnel.enroll"), slog.String("app.outcome", "denied"),
				slog.String("app.enrollment.id", enr), slog.String("client.address", ip))
			sconn.Close()
			return
		}
		dc.enroll = &codeLogin{enrollmentID: enr, publicKey: ext["public_key"]}
		dc.releaseCode = sync.OnceFunc(func() { s.releaseCodeLogin(enr) })
		defer dc.releaseCode()
		timer := time.AfterFunc(s.helloTimeout, func() {
			if dc.pendingEnrol() {
				dc.close("no hello")
			}
		})
		defer timer.Stop()
	} else {
		if d := s.cfg.Hooks.Device(dc.id); d != nil && manualTransport(d.Transport) {
			dc.manual = true
		}
		s.replace(dc)
	}
	dc.run(ctx, chans, reqs)
}

// manualTransport: a tunnel typed by a person (ADR-0005), not the watchdog.
func manualTransport(t string) bool {
	return t == model.TransportManual || t == model.TransportAttended
}

// Code-login limits. A valid code costs nothing against the wrong-code
// limiter (it is refunded), so what a code holder can open is capped here:
// logins waiting for hello per code and in total, and code checks per TCP
// connection (none + publickey queries).
const (
	maxCodeLoginsPerCode = 2
	maxCodeLoginsTotal   = 64
	maxCodeChecksPerConn = 3
)

func (s *Server) acquireCodeLogin(enrollmentID string) bool {
	s.codeMu.Lock()
	defer s.codeMu.Unlock()
	if s.codeLogins[enrollmentID] >= maxCodeLoginsPerCode || s.codeTotal >= maxCodeLoginsTotal {
		return false
	}
	s.codeLogins[enrollmentID]++
	s.codeTotal++
	return true
}

func (s *Server) releaseCodeLogin(enrollmentID string) {
	s.codeMu.Lock()
	defer s.codeMu.Unlock()
	if s.codeLogins[enrollmentID]--; s.codeLogins[enrollmentID] <= 0 {
		delete(s.codeLogins, enrollmentID)
	}
	s.codeTotal--
}

// allowCodeCheck counts one code lookup for the TCP connection behind meta.
func (s *Server) allowCodeCheck(meta ssh.ConnMetadata) bool {
	k := meta.RemoteAddr().String()
	s.codeMu.Lock()
	defer s.codeMu.Unlock()
	s.codeChecks[k]++
	return s.codeChecks[k] <= maxCodeChecksPerConn
}

// forgetCodeChecks drops a connection's count once its handshake ended.
func (s *Server) forgetCodeChecks(remoteAddr string) {
	s.codeMu.Lock()
	delete(s.codeChecks, remoteAddr)
	s.codeMu.Unlock()
}

// codeLogin is a login with an enrollment code, before its device exists.
type codeLogin struct {
	enrollmentID string
	publicKey    string
	redeeming    bool           // RedeemSSH is running: the hello timer must not close it
	done         bool           // hello handled (device created or refused)
	draining     bool           // held requests are being answered in order
	held         []*ssh.Request // every global request, in arrival order
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
	// ConnectionCode is set for typed (script-free) tunnels (ADR-0005).
	ConnectionCode string `json:"connection_code,omitempty"`
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

	// Script-free tunnels (ADR-0005). id is written once, under mu, when a
	// code login becomes a device; read it with devID() where that can race.
	enroll  *codeLogin // nil for a device login
	manual bool       // typed by a person: plain-language status lines, stdin unread
	code   string     // connection code shown to the person and on the device page
	// releaseCode frees this login's code-login slot (once; nil for device logins).
	releaseCode func()
}

func (dc *deviceConn) devID() string {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.id
}

// pendingEnrol: a code login that has not sent hello yet.
func (dc *deviceConn) pendingEnrol() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.enroll != nil && !dc.enroll.done && !dc.enroll.redeeming
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

func (dc *deviceConn) log() *slog.Logger {
	l := logx.L().With(slog.String("app.device.id", dc.devID()))
	if dc.enroll != nil {
		l = l.With(slog.String("app.enrollment.id", dc.enroll.enrollmentID))
	}
	return l
}

func (dc *deviceConn) scopeCtx(ctx context.Context) context.Context {
	if dc.id == "" {
		return ctx
	}
	d := dc.srv.cfg.Hooks.Device(dc.id)
	return logx.WithScope(ctx, logx.Scope{DeviceID: dc.id, Debug: d != nil && d.Debug})
}

func (dc *deviceConn) run(parent context.Context, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	ctx, cancel := context.WithCancel(dc.scopeCtx(parent))
	defer cancel()
	metrics.Default.Inc("remotehound_tunnel_connections_total", "Tunnel connections accepted.")
	dc.log().InfoContext(ctx, "Tunnel connected", logx.Event("tunnel.open"), slog.String("client.address", dc.remoteIP),
		slog.String("app.client_version", string(dc.conn.ClientVersion())))

	if dc.enroll == nil {
		go dc.keepalive(ctx) // a code login starts it once it is a device
	}
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
	id := dc.id
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
	if id == "" { // a code login that never became a device
		dc.log().Info("Tunnel closed", logx.Event("tunnel.close"), slog.String("app.reason", reason))
		return
	}
	wasCurrent := false
	dc.srv.mu.RLock()
	wasCurrent = dc.srv.conns[id] == dc
	dc.srv.mu.RUnlock()
	dc.srv.remove(dc)
	if wasCurrent {
		dc.srv.cfg.Hooks.Disconnected(id)
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
	ch, manual := dc.session, dc.manual
	dc.mu.Unlock()
	if manual { // a person reads this, not the watchdog
		switch line {
		case "revoked":
			line = "RemoteHound: this session was ended from the RemoteHound console."
		case "reconnect":
			line = "RemoteHound: the server closed this session. Run your command again to reconnect."
		default:
			return // no heartbeats in someone's terminal
		}
	}
	if ch != nil {
		_, _ = io.WriteString(ch, line+"\n")
	}
}

type tcpipForwardMsg struct {
	Addr string
	Port uint32
}

// handleGlobal answers a global request, or holds it while a code login has
// no device yet: replies must go out in request order, so everything that
// arrives before hello (and while the held ones drain) waits in line.
func (dc *deviceConn) handleGlobal(ctx context.Context, req *ssh.Request) {
	dc.mu.Lock()
	if e := dc.enroll; e != nil && (!e.done || e.draining) {
		if len(e.held) >= maxHeldForwards {
			dc.mu.Unlock()
			dc.log().WarnContext(ctx, "Too many requests before hello", logx.Event("tunnel.enroll"), slog.String("app.outcome", "denied"))
			dc.close("too many requests before hello")
			return
		}
		e.held = append(e.held, req)
		dc.mu.Unlock()
		return
	}
	dc.mu.Unlock()
	dc.answerGlobal(ctx, req)
}

// drainHeld answers held requests in order until none are left.
func (dc *deviceConn) drainHeld(ctx context.Context) {
	for {
		dc.mu.Lock()
		e := dc.enroll
		if len(e.held) == 0 {
			e.draining = false
			dc.mu.Unlock()
			return
		}
		req := e.held[0]
		e.held = e.held[1:]
		dc.mu.Unlock()
		dc.answerGlobal(ctx, req)
	}
}

func (dc *deviceConn) answerGlobal(ctx context.Context, req *ssh.Request) {
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
	if svc == nil && manualTransport(d.Transport) {
		// A typed ssh may send its -R requests after hello (clients need not
		// pipeline them): declare a conventional port, never any other.
		if kind := kindForPort(int(m.Port)); kind != "" && d.Service(kind) == nil {
			if err := dc.srv.cfg.Hooks.AddService(dc.id, kind, int(m.Port)); err != nil {
				return err
			}
			svc = &model.Service{Kind: kind, RemotePort: int(m.Port)}
		}
	}
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
	in := Info{DeviceID: dc.id, RemoteAddress: dc.remoteIP, ConnectedSince: dc.since, ClientVersion: dc.version, LastKeepaliveAt: dc.lastAlive,
		ConnectionCode: dc.code}
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
	dc.mu.Lock()
	typed := dc.manual || dc.enroll != nil // a person's ssh: hello, not agent
	dc.mu.Unlock()
	for req := range reqs {
		var cmd string
		switch {
		case req.Type == "exec":
			var m struct{ Command string }
			if ssh.Unmarshal(req.Payload, &m) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			cmd = m.Command
		case req.Type == "shell" && typed:
			cmd = "hello v1" // ssh with no command: answered as hello; no shell exists
		default:
			// shell (script devices), pty-req, x11-req, env, subsystem, auth-agent-req@openssh.com …
			_ = req.Reply(false, nil)
			continue
		}
		dc.mu.Lock()
		again := dc.execDone
		dc.execDone = true
		dc.mu.Unlock()
		if again { // one command per tunnel: no presence-write amplification
			_ = req.Reply(false, nil)
			continue
		}
		parse := ParseAgentCommand
		if typed {
			parse = ParseHello
		}
		facts, err := parse(cmd)
		if err != nil {
			_ = req.Reply(false, nil)
			dc.log().WarnContext(ctx, "Refused exec", logx.Event("tunnel.exec"), slog.String("app.outcome", "denied"), slog.String("app.reason", err.Error()))
			continue
		}
		_ = req.Reply(true, nil)
		if typed {
			dc.hello(ctx, ch, facts)
			continue
		}
		dc.mu.Lock()
		dc.session = ch
		dc.version = facts.ClientVersion
		dc.mu.Unlock()
		dc.srv.cfg.Hooks.Connected(dc.id, dc.remoteIP, facts)
		_, _ = io.WriteString(ch, "ok "+dc.id+"\n")
		go dc.readClientLog(ch)
	}
}

// hello handles a typed tunnel's hello: for a code login it creates the device
// first. It writes plain-language status lines; stdin (the person's keyboard)
// is never read.
func (dc *deviceConn) hello(ctx context.Context, ch ssh.Channel, facts Facts) {
	if facts.OS == "" && strings.Contains(string(dc.conn.ClientVersion()), "OpenSSH_for_Windows") {
		facts.OS = "windows"
	}
	reconnect := ""
	if dc.enroll != nil {
		enr := dc.srv.getEnroller()
		dc.mu.Lock()
		if enr == nil || dc.closed {
			dc.mu.Unlock()
			dc.close("no enroller")
			return
		}
		dc.enroll.redeeming = true // the hello timer leaves a redeem alone
		facts.Services = heldServices(dc.enroll.held)
		dc.mu.Unlock()
		r, err := enr.RedeemSSH(dc.enroll.enrollmentID, SSHEnrollment{IP: dc.remoteIP,
			Banner: string(dc.conn.ClientVersion()), PublicKey: dc.enroll.publicKey, Facts: facts})
		if err != nil {
			dc.mu.Lock()
			dc.enroll.done = true
			dc.mu.Unlock()
			dc.releaseCode()
			_, _ = io.WriteString(ch, "RemoteHound could not connect this machine: "+cleanLogLine(err.Error())+"\n")
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
			dc.log().WarnContext(ctx, "Enrollment over SSH refused", logx.Event("tunnel.enroll"), slog.String("app.outcome", "denied"), slog.String("app.reason", err.Error()))
			dc.close("enrollment refused")
			return
		}
		dc.mu.Lock()
		dc.id, dc.manual = r.DeviceID, true
		dc.enroll.done, dc.enroll.draining = true, true
		dc.mu.Unlock()
		dc.releaseCode()
		reconnect = r.Reconnect
		// Register, then re-check: a client that dropped right after hello was
		// closed before it was registered (its close could not unregister it),
		// so a closed conn found here is removed again instead of staying
		// "online" for good. (s.mu is taken before dc.mu elsewhere, so the
		// registration cannot sit inside the dc.mu section.)
		dc.srv.replace(dc)
		dc.mu.Lock()
		closed := dc.closed
		dc.mu.Unlock()
		if closed {
			dc.srv.remove(dc)
			return
		}
		go dc.keepalive(ctx)
		dc.drainHeld(ctx)
		dc.log().InfoContext(ctx, "Enrolled over SSH", logx.Event("tunnel.enroll"), slog.String("app.outcome", "success"))
	}
	name := dc.id
	if d := dc.srv.cfg.Hooks.Device(dc.id); d != nil && d.Name != "" {
		name = d.Name
	}
	code := connectionCode()
	dc.mu.Lock()
	dc.session, dc.code = ch, code
	dc.mu.Unlock()
	dc.srv.cfg.Hooks.Connected(dc.id, dc.remoteIP, facts)
	msg := "RemoteHound: connected as \"" + cleanLogLine(name) + "\".\n" +
		"Connection code: " + code + " (read it to the person helping you).\n"
	if reconnect != "" {
		msg += "To reconnect later without a new code, run:\n  " + reconnect + "\n"
	}
	msg += "Keep this window open. Close it, or press Ctrl+C, to end the session.\n"
	_, _ = io.WriteString(ch, msg)
}

// kindForPort maps a conventional port (22, 3389, 5900) to its kind, else "".
func kindForPort(port int) string {
	for kind, p := range model.DefaultRemotePort {
		if p == port {
			return kind
		}
	}
	return ""
}

// heldServices are the services named by held -R requests: only the
// conventional ports (22, 3389, 5900), each kind once.
func heldServices(held []*ssh.Request) []model.Service {
	var out []model.Service
	seen := map[string]bool{}
	for _, r := range held {
		var m tcpipForwardMsg
		if r.Type != "tcpip-forward" || ssh.Unmarshal(r.Payload, &m) != nil {
			continue
		}
		if kind := kindForPort(int(m.Port)); kind != "" && !seen[kind] {
			seen[kind] = true
			out = append(out, model.Service{Kind: kind, RemotePort: int(m.Port)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RemotePort < out[j].RemotePort })
	return out
}

// connectionCode is 4 characters from the code alphabet, upper case, for a
// person to read out over the phone.
func connectionCode() string { return strings.ToUpper(ids.Code()[:4]) }

// ConnectionCode returns the live typed tunnel's connection code ("" if none).
func (s *Server) ConnectionCode(deviceID string) string {
	s.mu.RLock()
	dc := s.conns[deviceID]
	s.mu.RUnlock()
	if dc == nil {
		return ""
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.code
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
		lines = append(lines, cleanLogLine(line))
	}
	if len(lines) > 0 {
		dc.srv.cfg.Hooks.ClientLog(dc.id, lines)
	}
}

// cleanLogLine makes a device-supplied log line safe to show: valid UTF-8,
// without control characters (C0 except tab, DEL, C1: terminal escapes in a
// CLI), format characters (Cf: bidi controls, zero-width characters, BOM,
// interlinear annotations, tag characters: text that reads differently from
// what it is) or line/paragraph separators (Zl, Zp).
func cleanLogLine(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return r
		case r < 0x20, r >= 0x7f && r <= 0x9f, unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}

// ParseAgentCommand validates `agent v1 key=value …` and extracts facts.
// Unknown keys are ignored (forward-compatible); values are length- and
// charset-limited.
func ParseAgentCommand(cmd string) (Facts, error) {
	return parseFacts(cmd, "agent")
}

// ParseHello validates a typed tunnel's `hello v1 [os=…] [host=…]` (ADR-0005).
// The person's shell expands the values ($(uname -s), %COMPUTERNAME%), so os
// also accepts uname's spelling: Darwin, Linux.
func ParseHello(cmd string) (Facts, error) {
	return parseFacts(cmd, "hello")
}

func parseFacts(cmd, verb string) (Facts, error) {
	var f Facts
	fields := strings.Fields(cmd)
	if len(fields) < 2 || fields[0] != verb || fields[1] != "v1" {
		return f, errors.New("not a " + verb + " v1 command")
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
			case "Linux":
				f.OS = "linux"
			case "Darwin":
				f.OS = "macos"
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
