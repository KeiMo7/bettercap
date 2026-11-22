package http_proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	btls "github.com/bettercap/bettercap/v2/tls"

	"github.com/inconshreveable/go-vhost"
)

const (
	defaultPassthroughTTL   = time.Hour
	defaultHandshakeTimeout = 10 * time.Second

	// silentHandshakeThreshold is how many consecutive decrypted connections to
	// the same host must complete TLS and then send no application data before
	// pinning is suspected. Browser preconnect sockets produce one or two of
	// these normally, so a single one is not evidence.
	silentHandshakeThreshold = 3
)

// silentHandshakeState tracks consecutive silent (no application data) TLS
// connections per host. Only reached from the adaptive path.
type silentHandshakeState struct {
	count uint32
	last  time.Time
}

// passthroughMark records why and until a host should bypass MITM. Using a TTL
// means a host is retried after a client trust store is fixed or a transient
// pinning verdict changes, instead of being blacklisted forever.
type passthroughMark struct {
	outcome ConnectionOutcome
	reason  string
	until   time.Time
}

// TLSConnectionEvent is emitted for every handled TLS connection so external
// tooling can build its own per-site reports.
type TLSConnectionEvent struct {
	Host              string            `json:"host"`
	Category          SiteCategory      `json:"category"`
	Decrypted         bool              `json:"decrypted"`
	Outcome           ConnectionOutcome `json:"outcome"`
	Reason            string            `json:"reason,omitempty"`
	Handshake         time.Duration     `json:"handshake"`
	UpstreamVerified  bool              `json:"upstream_verified"`
	UpstreamVerifyErr string            `json:"upstream_verify_error,omitempty"`
}

func (p *HTTPProxy) HTTPSStats() HTTPSProxyStats {
	if p.stats == nil {
		return HTTPSProxyStats{CertCache: certCacheStats(), ByOutcome: map[ConnectionOutcome]uint64{}}
	}
	return p.stats.snapshot()
}

func (p *HTTPProxy) ResetHTTPSStats() {
	if p.stats != nil {
		p.stats.reset()
	}
	certStore.resetStats()
}

// ConfigureAdaptive wires the passthrough policy, upstream lookup timeout and
// bounded certificate prewarming. It is safe to call while stopped only.
func (p *HTTPProxy) ConfigureAdaptive(enabled bool, passthroughTTL time.Duration, upstreamTimeout time.Duration, prewarm []string, prewarmMax int) {
	p.adaptive = enabled
	if passthroughTTL > 0 {
		p.passthroughTTL = passthroughTTL
	}
	if upstreamTimeout > 0 {
		p.upstreamTimeout = upstreamTimeout
	}
	if prewarmMax > 0 {
		p.prewarmMax = prewarmMax
	}
	p.prewarmDomains = normalizeDomainList(prewarm, p.prewarmMax)
}

func (p *HTTPProxy) ConfigureCertificateCache(capacity int, ttl time.Duration) {
	certStore.configure(capacity, ttl)
}

func normalizeDomainList(domains []string, max int) []string {
	if max <= 0 {
		max = 32
	}

	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = normalizeCacheDomain(domain)
		if domain == "" || strings.ContainsAny(domain, "/* \t\r\n") {
			continue
		}
		if _, found := seen[domain]; found {
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
		if len(normalized) >= max {
			break
		}
	}
	return normalized
}

// prewarmCertificates issues certificates for a bounded, operator supplied list
// of common hosts so their first real handshake does not pay the issuance cost.
func (p *HTTPProxy) prewarmCertificates() {
	if p.ca == nil || len(p.prewarmDomains) == 0 {
		return
	}

	domains := append([]string(nil), p.prewarmDomains...)
	p.Info("prewarming %d dynamic certificates", len(domains))
	go func() {
		for _, host := range domains {
			if !p.isRunning.Load() {
				return
			}
			_, _, _, err := getOrCreateCert(host, p.upstreamPort, func() (*tls.Certificate, error) {
				cert, _, err := p.certificateForHost(p.ca, host, p.upstreamPort)
				return cert, err
			})
			if err != nil {
				p.Debug("could not prewarm certificate for %s: %s", host, err)
			}
		}
	}()
}

func (p *HTTPProxy) isPassthrough(host string) (passthroughMark, bool) {
	host = normalizeCacheDomain(host)
	now := time.Now()

	p.passthroughMu.RLock()
	mark, found := p.passthrough[host]
	p.passthroughMu.RUnlock()
	if !found {
		return passthroughMark{}, false
	}
	if !mark.until.After(now) {
		p.passthroughMu.Lock()
		delete(p.passthrough, host)
		p.passthroughMu.Unlock()
		return passthroughMark{}, false
	}
	return mark, true
}

func (p *HTTPProxy) markPassthrough(host string, outcome ConnectionOutcome, reason string) {
	if p.passthroughTTL <= 0 {
		p.passthroughTTL = defaultPassthroughTTL
	}
	host = normalizeCacheDomain(host)
	if host == "" {
		return
	}

	p.passthroughMu.Lock()
	if p.passthrough == nil {
		p.passthrough = make(map[string]passthroughMark)
	}
	p.passthrough[host] = passthroughMark{
		outcome: outcome,
		reason:  reason,
		until:   time.Now().Add(p.passthroughTTL),
	}
	// A host that is now in passthrough starts with a clean silent-handshake
	// record, so the verdict is not immediately re-triggered after the TTL.
	delete(p.silentHandshakes, host)
	p.passthroughMu.Unlock()
}

// confirmSilentHandshake increments the consecutive silent-handshake counter
// for a host and reports whether the pinning threshold was reached. The counter
// decays after the passthrough TTL, mirroring the passthrough decision, so a
// host is eventually retried for MITM instead of being marked forever.
func (p *HTTPProxy) confirmSilentHandshake(host string) bool {
	host = normalizeCacheDomain(host)
	if host == "" {
		return false
	}
	ttl := p.passthroughTTL
	if ttl <= 0 {
		ttl = defaultPassthroughTTL
	}
	now := time.Now()

	p.passthroughMu.Lock()
	defer p.passthroughMu.Unlock()
	if p.silentHandshakes == nil {
		p.silentHandshakes = make(map[string]*silentHandshakeState)
	}
	state := p.silentHandshakes[host]
	if state == nil || now.Sub(state.last) > ttl {
		state = &silentHandshakeState{}
		p.silentHandshakes[host] = state
	}
	state.count++
	state.last = now
	return state.count >= silentHandshakeThreshold
}

func (p *HTTPProxy) clearSilentHandshake(host string) {
	p.passthroughMu.Lock()
	delete(p.silentHandshakes, normalizeCacheDomain(host))
	p.passthroughMu.Unlock()
}

func (p *HTTPProxy) recordTLSConnection(host string, outcome ConnectionOutcome, decrypted bool, reason string, handshake time.Duration, upstream *btls.UpstreamCertificate) {
	category := classifySite(host)
	if p.stats != nil {
		p.stats.record(category, outcome, handshake)
	}

	event := TLSConnectionEvent{
		Host:      host,
		Category:  category,
		Decrypted: decrypted,
		Outcome:   outcome,
		Reason:    reason,
		Handshake: handshake,
	}
	if upstream != nil {
		event.UpstreamVerified = upstream.Verified
		if upstream.VerificationErr != nil {
			event.UpstreamVerifyErr = upstream.VerificationErr.Error()
		}
	}
	if p.Sess != nil && p.Sess.Events != nil {
		p.Sess.Events.Add(p.Name+".tls-connection", event)
	}

	if decrypted {
		p.Debug("TLS decrypted for %s (%s, handshake %s)", host, category, handshake.Round(time.Millisecond))
	} else {
		// Never fail silently: a passthrough connection is explicitly labelled
		// as not decrypted, together with the reason and its category.
		p.Warning("TLS passthrough for %s (%s): connection is NOT decrypted (%s)", host, category, reason)
	}
}

// certificateForHost fetches the origin certificate through the proxy's own
// dial path, then signs a leaf covering the SNI host and its sibling names.
func (p *HTTPProxy) certificateForHost(ca *tls.Certificate, host string, port int) (*tls.Certificate, *btls.SignInfo, error) {
	started := time.Now()
	info := &btls.SignInfo{Host: host}

	var connectDial btls.DialFunc
	if p.Proxy != nil {
		connectDial = p.Proxy.ConnectDial
	}
	upstream, err := btls.FetchServerCertificateWithDialer(host, port, p.upstreamTimeout, connectDial)
	if err != nil {
		info.UpstreamFetchErr = err
		p.Debug("upstream certificate unavailable for %s:%d, signing from SNI only: %s", host, port, err)
	} else {
		info.Upstream = upstream
	}

	var upstreamLeaf *x509.Certificate
	if upstream != nil {
		upstreamLeaf = upstream.Leaf
		if upstream.VerificationErr != nil {
			// An invalid origin certificate is a finding to report, not a
			// reason to break the connection.
			p.Warning("upstream certificate validation failed for %s:%d, continuing: %s", host, port, upstream.VerificationErr)
			if p.Sess != nil && p.Sess.Events != nil {
				p.Sess.Events.Add(p.Name+".upstream-verification", TLSConnectionEvent{
					Host:              host,
					Category:          classifySite(host),
					UpstreamVerified:  false,
					UpstreamVerifyErr: upstream.VerificationErr.Error(),
				})
			}
		}
	}

	names := btls.CertificateNamesForHost(host, upstreamLeaf)
	info.DNSNames = append([]string(nil), names...)
	cert, err := btls.SignCertificateForNames(ca, host, names, upstreamLeaf)
	if err != nil {
		return nil, info, err
	}
	info.Elapsed = time.Since(started)
	return cert, info, nil
}

// serveAdaptive terminates (or tunnels) one already parsed TLS connection. It
// is only used when https.proxy.adaptive is enabled; the default path is
// unchanged goproxy MITM.
func (p *HTTPProxy) serveAdaptive(conn *vhost.TLSConn, host string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	if mark, passthrough := p.isPassthrough(host); passthrough {
		p.tunnel(conn, host, mark.outcome, mark.reason, nil)
		return
	}

	var info *btls.SignInfo
	cert, _, issueElapsed, err := getOrCreateCert(host, p.upstreamPort, func() (*tls.Certificate, error) {
		cert, signInfo, err := p.certificateForHost(p.ca, host, p.upstreamPort)
		info = signInfo
		return cert, err
	})

	var upstream *btls.UpstreamCertificate
	if info != nil {
		upstream = info.Upstream
	}

	if err != nil {
		// No usable certificate: transparent passthrough, explicitly labelled.
		reason := fmt.Sprintf("certificate issuance failed: %v", err)
		p.markPassthrough(host, OutcomePassthroughSignFailure, reason)
		p.tunnel(conn, host, OutcomePassthroughSignFailure, reason, upstream)
		return
	}
	if issueElapsed > 0 {
		p.Debug("signed certificate for %s in %s", host, issueElapsed.Round(time.Millisecond))
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	tlsConn := tls.Server(conn, tlsConfig)

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), defaultHandshakeTimeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// A failed handshake cannot be replayed on this same TCP connection:
		// the certificate has already been sent. The first connection fails,
		// is classified and reported, and subsequent ones are passed through.
		elapsed := time.Since(started)
		outcome, reason := classifyClientHandshakeFailure(err, host, cert)
		p.markPassthrough(host, outcome, reason)
		p.recordTLSConnection(host, outcome, false, reason, elapsed, upstream)
		return
	}
	handshakeElapsed := time.Since(started)

	p.serveDecrypted(conn, tlsConn, host, handshakeElapsed, upstream)
}

// serveDecrypted feeds the decrypted connection into the existing goproxy
// pipeline, so scripts, filters and injection keep working unchanged.
func (p *HTTPProxy) serveDecrypted(rawConn net.Conn, tlsConn *tls.Conn, host string, handshake time.Duration, upstream *btls.UpstreamCertificate) {
	observed := &observedConn{Conn: tlsConn}
	listener := &singleConnListener{
		conn: observed,
		done: make(chan struct{}),
	}
	observed.done = listener.done

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL != nil {
			req.URL.Scheme = "https"
			req.URL.Host = req.Host
		}
		p.Proxy.ServeHTTP(w, req)
	})
	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	observed.onClose = func(gotApplicationData bool) {
		if gotApplicationData {
			p.clearSilentHandshake(host)
			p.recordTLSConnection(host, OutcomeDecrypted, true, "", handshake, upstream)
			return
		}

		// A client that completes TLS and then closes without sending bytes is
		// the characteristic signature of an application-layer pinning check.
		// Browsers also open speculative (preconnect) sockets that behave the
		// same way, so one silent connection is not enough evidence: a host is
		// only moved to passthrough after several. This is never inferred from
		// network or handshake failures.
		if p.isRunning.Load() && p.confirmSilentHandshake(host) {
			reason := "client completed TLS handshake but sent no application data on repeated connections; possible certificate pinning"
			p.markPassthrough(host, OutcomePassthroughPinning, reason)
			p.recordTLSConnection(host, OutcomePassthroughPinning, false, reason, handshake, upstream)
			return
		}
		p.recordTLSConnection(host, OutcomeDecrypted, true, "", handshake, upstream)
	}

	_ = server.Serve(listener)
	_ = rawConn.Close()
}

// tunnel forwards the raw TLS bytes to the origin without decrypting them.
// outcome is passed in explicitly rather than re-derived from the human
// readable reason, so the reported classification is always the real cause.
func (p *HTTPProxy) tunnel(conn *vhost.TLSConn, host string, outcome ConnectionOutcome, reason string, upstream *btls.UpstreamCertificate) {
	started := time.Now()
	target, err := p.dialTunnelTarget(host)
	if err != nil {
		p.recordTLSConnection(host, OutcomeUpstreamError, false, "upstream connection failed: "+err.Error(), time.Since(started), nil)
		return
	}
	defer target.Close()

	p.recordTLSConnection(host, outcome, false, reason, 0, upstream)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, conn)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, target)
		if tcp, ok := conn.Conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	wg.Wait()
}

func (p *HTTPProxy) dialTunnelTarget(host string) (net.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.upstreamPort))
	if p.Proxy != nil && p.Proxy.ConnectDial != nil {
		return p.Proxy.ConnectDial("tcp", addr)
	}

	dialer := &net.Dialer{Timeout: p.upstreamTimeout, KeepAlive: 30 * time.Second}
	return dialer.Dial("tcp", addr)
}

// classifyClientHandshakeFailure separates the three actionable causes: the
// client does not trust the proxy CA (install it), the name did not match
// (inspect generated SANs) and everything else.
func classifyClientHandshakeFailure(err error, host string, cert *tls.Certificate) (ConnectionOutcome, string) {
	message := strings.ToLower(err.Error())
	if cert != nil && cert.Leaf != nil {
		if nameErr := cert.Leaf.VerifyHostname(host); nameErr != nil {
			return OutcomePassthroughNameMismatch, "certificate name mismatch: " + nameErr.Error()
		}
	}

	if strings.Contains(message, "hostname") || strings.Contains(message, "name mismatch") {
		return OutcomePassthroughNameMismatch, "certificate name mismatch: " + err.Error()
	}

	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) ||
		strings.Contains(message, "unknown certificate authority") ||
		strings.Contains(message, "unknown ca") ||
		strings.Contains(message, "bad certificate") {
		return OutcomePassthroughUntrustedCA, "client rejected the proxy CA; install the CA certificate or use passthrough: " + err.Error()
	}

	return OutcomePassthroughTLSFailure, "client TLS handshake failed: " + err.Error()
}

// observedConn records whether the decrypted peer ever sent application data,
// which is how pinning is distinguished from a broken client.
type observedConn struct {
	net.Conn
	read      atomic.Bool
	closeOnce sync.Once
	onClose   func(bool)
	done      chan struct{}
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read.Store(true)
	}
	return n, err
}

func (c *observedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose(c.read.Load())
		}
		if c.done != nil {
			close(c.done)
		}
	})
	return err
}

// singleConnListener adapts one hijacked connection to http.Server.
type singleConnListener struct {
	conn     net.Conn
	done     chan struct{}
	accepted atomic.Bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.accepted.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	<-l.done
	return nil, io.EOF
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return dummyAddr("mitm")
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
