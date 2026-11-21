package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ProbeResult reports whether a service answers through the tunnel.
type ProbeResult struct {
	Service   string `json:"service"`
	OK        bool   `json:"ok"`
	Banner    string `json:"banner"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// Probe opens a channel to the device's forward for kind and checks the
// protocol greeting: SSH and VNC servers speak first; for RDP
// we send an X.224 Connection Request and expect a TPKT reply.
func (s *Server) Probe(ctx context.Context, deviceID, kind string, remotePort int) ProbeResult {
	r := ProbeResult{Service: kind}
	s.mu.RLock()
	dc := s.conns[deviceID]
	s.mu.RUnlock()
	var f *forward
	if dc != nil {
		dc.mu.Lock()
		f = dc.forwards[remotePort]
		dc.mu.Unlock()
	}
	if f == nil {
		r.Error = "not forwarded"
		r.Hint = "The device is offline or did not forward this port. Check the service is enabled on the device and listed under Services."
		return r
	}
	// Probe over a forwarded-tcpip channel opened directly on the device's SSH
	// connection — never through the tunnel listener, so a probe can never be
	// mistaken for (or steal the attribution of) an operator's session.
	start := time.Now()
	payload := ssh.Marshal(forwardedTCPPayload{Addr: f.bindAddr, Port: uint32(f.remotePort), OriginAddr: "127.0.0.1", OriginPort: 65535}) // OpenSSH rejects origin port 0
	ch, reqs, err := dc.conn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()
	type result struct {
		banner string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		switch kind {
		case "rdp":
			// TPKT(3,0,len=19) + X.224 CR + RDP_NEG_REQ(protocols=TLS|HYBRID)
			cr := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
			if _, err := ch.Write(cr); err != nil {
				done <- result{err: err}
				return
			}
			buf := make([]byte, 19)
			n, err := io.ReadAtLeast(ch, buf, 4)
			if err == nil && (n < 4 || buf[0] != 0x03 || buf[1] != 0x00) {
				err = errors.New("unexpected reply (not RDP)")
			}
			done <- result{banner: "X.224 connection confirm", err: err}
		default:
			buf := make([]byte, 64)
			n, err := ch.Read(buf)
			b := strings.TrimSpace(string(bytes.ToValidUTF8(buf[:n], nil)))
			if err == nil && !(kind == "ssh" && strings.HasPrefix(b, "SSH-")) && !(kind == "vnc" && strings.HasPrefix(b, "RFB ")) {
				err = errors.New("unexpected greeting for " + kind)
			}
			done <- result{banner: b, err: err}
		}
	}()
	var res result
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		res.err = errors.New("timeout waiting for the service")
	case <-ctx.Done():
		res.err = ctx.Err()
	}
	r.LatencyMS = time.Since(start).Milliseconds()
	r.Banner = res.banner
	if res.err != nil {
		r.Error = res.err.Error()
		switch {
		case errors.Is(res.err, io.EOF):
			r.Hint = "The tunnel is up but nothing is listening on the device's port. Enable the service on the device (Remote Login / Screen Sharing / Remote Desktop)."
		case strings.Contains(res.err.Error(), "timeout"):
			r.Hint = "No reply in 5 s. The service may be blocked by a local firewall on loopback or be very slow."
		}
		return r
	}
	r.OK = true
	return r
}
