package http_proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	btls "github.com/bettercap/bettercap/v2/tls"

	"github.com/elazarl/goproxy"
)

// adaptiveTestProxy wires a real HTTPS proxy in front of an httptest TLS
// server, with the proxy's dial path redirected to that server.
type adaptiveTestProxy struct {
	proxy *HTTPProxy
	addr  string
	roots *x509.CertPool
	// hits counts requests that reached the origin.
	hits    int32
	hitsMux sync.Mutex
}

func (p *adaptiveTestProxy) requestCount() int32 {
	p.hitsMux.Lock()
	defer p.hitsMux.Unlock()
	return p.hits
}

func newAdaptiveTestProxy(t *testing.T, adaptive bool) *adaptiveTestProxy {
	t.Helper()
	resetCertCache()
	t.Cleanup(resetCertCache)

	fixture := &adaptiveTestProxy{}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fixture.hitsMux.Lock()
		fixture.hits++
		fixture.hitsMux.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok:"+req.Host)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.cert.pem")
	keyFile := filepath.Join(dir, "ca.key.pem")
	cfg := btls.DefaultLegitConfig
	cfg.Bits = 2048
	if err := btls.Generate(cfg, certFile, keyFile, true); err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not parse generated CA")
	}

	sess, _ := createMockSession()
	proxy := NewHTTPProxy(sess, "test")
	if err := proxy.ConfigureTLS("127.0.0.1", 0, 0, false, "", certFile, keyFile, "", false); err != nil {
		t.Fatal(err)
	}

	upstreamAddr := upstream.Listener.Addr().String()
	proxy.upstreamPort = upstream.Listener.Addr().(*net.TCPAddr).Port
	proxy.ConfigureAdaptive(adaptive, time.Minute, time.Second, nil, 2)
	proxy.Proxy.Tr = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.Proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		return net.Dial(network, upstreamAddr)
	}

	proxy.Start()
	select {
	case <-proxy.started:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not start")
	}
	t.Cleanup(func() {
		_ = proxy.Stop()
	})

	fixture.proxy = proxy
	fixture.addr = proxy.sniListener.Addr().String()
	fixture.roots = roots
	return fixture
}

func (p *adaptiveTestProxy) clientTLSConfig(serverName string, trustProxy bool) *tls.Config {
	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if trustProxy {
		cfg.RootCAs = p.roots
	} else {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

func httpsRequest(t *testing.T, proxyAddr string, cfg *tls.Config) (string, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()

	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		return "", err
	}
	defer conn.Close()

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", cfg.ServerName)
	if _, err := io.WriteString(conn, req); err != nil {
		return "", err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return string(body), nil
}

func waitForStats(t *testing.T, proxy *HTTPProxy, check func(HTTPSProxyStats) bool) HTTPSProxyStats {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stats := proxy.HTTPSStats()
		if check(stats) {
			return stats
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats := proxy.HTTPSStats()
	t.Fatalf("stats condition not met: %+v", stats)
	return stats
}

func TestAdaptiveProxyDecryptsWithTrustedCA(t *testing.T) {
	testProxy := newAdaptiveTestProxy(t, true)
	body, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("example.com", true))
	if err != nil {
		t.Fatal(err)
	}
	if body != "ok:example.com" {
		t.Fatalf("unexpected body: %s", body)
	}
	if body, err = httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("api.example.com", true)); err != nil {
		t.Fatalf("sibling subdomain must reuse the cached certificate: %v", err)
	}
	if body != "ok:api.example.com" {
		t.Fatalf("unexpected sibling body: %s", body)
	}

	stats := waitForStats(t, testProxy.proxy, func(stats HTTPSProxyStats) bool {
		return stats.Total >= 2
	})
	if stats.Decrypted != 2 {
		t.Fatalf("expected two decrypted connections: %+v", stats)
	}
	if stats.CertCache.CertificatesIssued != 1 {
		t.Fatalf("expected a single issuance covering both subdomains, got %d", stats.CertCache.CertificatesIssued)
	}
	if stats.CertCache.Hits == 0 {
		t.Fatal("expected the second handshake to hit the certificate cache")
	}
	if testProxy.requestCount() != 2 {
		t.Fatalf("expected both requests to reach the origin, got %d", testProxy.requestCount())
	}
}

func TestAdaptiveProxyFallsBackAfterClientRejectsCA(t *testing.T) {
	testProxy := newAdaptiveTestProxy(t, true)

	// A client that validates against the system roots rejects our CA.
	_, err := httpsRequest(t, testProxy.addr, &tls.Config{
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("expected the first untrusted handshake to fail")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, passthrough := testProxy.proxy.isPassthrough("example.com"); passthrough {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy did not learn to pass through the rejected host")
		}
		time.Sleep(10 * time.Millisecond)
	}

	body, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("example.com", false))
	if err != nil {
		t.Fatalf("passthrough connection failed: %v", err)
	}
	if body != "ok:example.com" {
		t.Fatalf("unexpected passthrough body: %s", body)
	}

	stats := waitForStats(t, testProxy.proxy, func(stats HTTPSProxyStats) bool {
		return stats.Total >= 2
	})
	if stats.ClientErrors == 0 {
		t.Fatalf("expected a client certificate error: %+v", stats)
	}
	if stats.ByOutcome[OutcomePassthroughUntrustedCA] == 0 {
		t.Fatalf("expected untrusted CA classification: %+v", stats.ByOutcome)
	}
	if stats.Passthrough == 0 {
		t.Fatalf("expected passthrough count: %+v", stats)
	}
	if stats.Decrypted != 0 {
		t.Fatalf("the rejected host must not be reported as decrypted: %+v", stats)
	}
}

func TestAdaptiveProxyPassesThroughWhenSigningFails(t *testing.T) {
	testProxy := newAdaptiveTestProxy(t, true)
	testProxy.proxy.ca = nil

	body, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("example.com", false))
	if err != nil {
		t.Fatalf("fallback connection failed: %v", err)
	}
	if body != "ok:example.com" {
		t.Fatalf("unexpected fallback body: %s", body)
	}

	stats := waitForStats(t, testProxy.proxy, func(stats HTTPSProxyStats) bool {
		return stats.Total >= 1
	})
	if stats.ByOutcome[OutcomePassthroughSignFailure] == 0 {
		t.Fatalf("expected signing failure classification: %+v", stats.ByOutcome)
	}
	if stats.ClientErrors != 0 {
		t.Fatalf("a signing failure must not be counted as a client error: %+v", stats)
	}
}

func TestAdaptiveProxyMarksPinningAfterSuccessfulHandshakeWithoutApplicationData(t *testing.T) {
	testProxy := newAdaptiveTestProxy(t, true)

	// A single silent connection is normal (browser preconnect), so repeat it
	// until the confirmation threshold is reached.
	for i := 0; i < silentHandshakeThreshold; i++ {
		raw, err := net.DialTimeout("tcp", testProxy.addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn := tls.Client(raw, testProxy.clientTLSConfig("example.com", true))
		if err := conn.Handshake(); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		_ = raw.Close()
	}

	stats := waitForStats(t, testProxy.proxy, func(stats HTTPSProxyStats) bool {
		return stats.ByOutcome[OutcomePassthroughPinning] > 0
	})
	if stats.ClientErrors == 0 {
		t.Fatalf("expected the pinning suspicion to count as a client error: %+v", stats)
	}
	if mark, passthrough := testProxy.proxy.isPassthrough("example.com"); !passthrough || mark.outcome != OutcomePassthroughPinning || !strings.Contains(mark.reason, "pinning") {
		t.Fatalf("expected pinning passthrough mark, got %+v (%v)", mark, passthrough)
	}
}

func TestAdaptiveProxyDoesNotMarkPinningOnSingleSilentConnection(t *testing.T) {
	// Browser preconnect sockets complete TLS and close without sending data.
	// One such connection must not disable decryption for the host.
	testProxy := newAdaptiveTestProxy(t, true)

	raw, err := net.DialTimeout("tcp", testProxy.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, testProxy.clientTLSConfig("example.com", true))
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = raw.Close()

	waitForStats(t, testProxy.proxy, func(stats HTTPSProxyStats) bool {
		return stats.Total >= 1
	})
	if _, passthrough := testProxy.proxy.isPassthrough("example.com"); passthrough {
		t.Fatal("a single silent connection must not trigger passthrough")
	}

	body, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("example.com", true))
	if err != nil {
		t.Fatalf("host should still be decrypted: %v", err)
	}
	if body != "ok:example.com" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestSyncSilentHandshakeClearedByRealTraffic(t *testing.T) {
	sess, _ := createMockSession()
	proxy := NewHTTPProxy(sess, "test")

	for i := 1; i < silentHandshakeThreshold; i++ {
		if proxy.confirmSilentHandshake("example.com") {
			t.Fatal("threshold reached too early")
		}
	}
	proxy.clearSilentHandshake("example.com")
	if proxy.confirmSilentHandshake("example.com") {
		t.Fatal("real traffic must reset the consecutive silent counter")
	}
}

func TestAdaptiveProxyRecordsUpstreamVerificationFailureAndKeepsDecrypting(t *testing.T) {
	testProxy := newAdaptiveTestProxy(t, true)

	body, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("example.com", true))
	if err != nil {
		t.Fatal(err)
	}
	if body != "ok:example.com" {
		t.Fatalf("unexpected body: %s", body)
	}

	// The httptest origin uses a private CA, so upstream verification must fail
	// while the decrypted transaction still succeeds.
	stats := waitForStats(t, testProxy.proxy, func(stats HTTPSProxyStats) bool {
		return stats.Decrypted >= 1
	})
	if stats.UpstreamErrors != 0 {
		t.Fatalf("an invalid upstream certificate must not break forwarding: %+v", stats)
	}
	if stats.Decrypted != 1 {
		t.Fatalf("expected the connection to be decrypted: %+v", stats)
	}
}

func TestAdaptiveProxyPassthroughIsLabelledInEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("network timeout test")
	}

	sess, _ := createMockSession()
	proxy := NewHTTPProxy(sess, "test")
	upstream := &btls.UpstreamCertificate{}
	proxy.recordTLSConnection("bank.example.com", OutcomePassthroughPinning, false, "pinning", time.Millisecond, upstream)

	stats := proxy.HTTPSStats()
	if stats.Decrypted != 0 || stats.ByOutcome[OutcomePassthroughPinning] != 1 {
		t.Fatalf("a passthrough connection must never be reported as decrypted: %+v", stats)
	}
}

func TestDefaultModePassesThroughWhenSigningFails(t *testing.T) {
	// Default (non adaptive) mode keeps its always-MITM behavior, but must not
	// break the connection when a certificate cannot be issued: it degrades to
	// a transparent tunnel and records the connection as not decrypted.
	resetCertCache()
	t.Cleanup(resetCertCache)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "ok:"+req.Host)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.cert.pem")
	keyFile := filepath.Join(dir, "ca.key.pem")
	cfg := btls.DefaultLegitConfig
	cfg.Bits = 2048
	if err := btls.Generate(cfg, certFile, keyFile, true); err != nil {
		t.Fatal(err)
	}

	sess, _ := createMockSession()
	proxy := NewHTTPProxy(sess, "test")
	if err := proxy.ConfigureTLS("127.0.0.1", 0, 0, false, "", certFile, keyFile, "", false); err != nil {
		t.Fatal(err)
	}
	upstreamAddr := upstream.Listener.Addr().String()
	proxy.Proxy.Tr = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.Proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		return net.Dial(network, upstreamAddr)
	}
	// Force issuance to fail after the cache miss.
	proxy.ca = nil

	action, _ := proxy.onConnect("example.com:443", nil)
	if action.Action != goproxy.ConnectAccept {
		t.Fatalf("expected transparent accept when issuance fails, got %d", action.Action)
	}

	stats := proxy.HTTPSStats()
	if stats.ByOutcome[OutcomePassthroughSignFailure] != 1 {
		t.Fatalf("expected the connection to be recorded as undecrypted: %+v", stats.ByOutcome)
	}
	if stats.Decrypted != 0 {
		t.Fatalf("a passthrough connection must not be reported as decrypted: %+v", stats)
	}
}

func TestDefaultModeStillDecryptsWithTrustedCA(t *testing.T) {
	// Non adaptive mode must keep the original always-MITM behavior.
	testProxy := newAdaptiveTestProxy(t, false)

	body, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("example.com", true))
	if err != nil {
		t.Fatal(err)
	}
	if body != "ok:example.com" {
		t.Fatalf("unexpected body: %s", body)
	}
	if testProxy.requestCount() != 1 {
		t.Fatalf("expected the request to reach the origin, got %d", testProxy.requestCount())
	}
	if stats := testProxy.proxy.HTTPSStats(); stats.Decrypted != 1 {
		t.Fatalf("default mode must report the decrypted connection: %+v", stats)
	}
}

func TestDefaultModeUsesSiblingWildcardCertificate(t *testing.T) {
	// A freshly signed certificate covers sibling subdomains, so the second
	// hostname must not trigger a second issuance.
	testProxy := newAdaptiveTestProxy(t, false)

	if _, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("www.example.com", true)); err != nil {
		t.Fatal(err)
	}
	if _, err := httpsRequest(t, testProxy.addr, testProxy.clientTLSConfig("api.example.com", true)); err != nil {
		t.Fatalf("sibling hostname must reuse the issued certificate: %v", err)
	}

	stats := testProxy.proxy.HTTPSStats()
	if stats.CertCache.CertificatesIssued != 1 {
		t.Fatalf("expected a single issuance for sibling hosts, got %d", stats.CertCache.CertificatesIssued)
	}
}
