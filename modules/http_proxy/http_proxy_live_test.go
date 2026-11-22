package http_proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	btls "github.com/bettercap/bettercap/v2/tls"
)

// TestLiveSiteDecryptRatio is an opt-in measurement against real sites. It is
// skipped by default; enable it with:
//
//	BETTERCAP_LIVE_TLS=1 go test ./modules/http_proxy/ -run TestLiveSiteDecryptRatio -v
//
// BETTERCAP_LIVE_HOSTS may override the site list (comma separated). Results
// are reported per site category (static, api, banking, other), because a
// single aggregate ratio hides the large differences between them.
func TestLiveSiteDecryptRatio(t *testing.T) {
	if os.Getenv("BETTERCAP_LIVE_TLS") == "" {
		t.Skip("set BETTERCAP_LIVE_TLS=1 to run live HTTPS interception measurements")
	}

	hosts := []string{
		"www.wikipedia.org", "www.example.com", "www.cloudflare.com",
		"api.github.com", "api.stripe.com",
		"www.paypal.com", "www.chase.com",
	}
	if override := os.Getenv("BETTERCAP_LIVE_HOSTS"); override != "" {
		hosts = strings.Split(override, ",")
	}

	dir := t.TempDir()
	certFile := dir + "/ca.cert.pem"
	keyFile := dir + "/ca.key.pem"
	cfg := btls.DefaultLegitConfig
	cfg.Bits = 2048
	if err := btls.Generate(cfg, certFile, keyFile, true); err != nil {
		t.Fatal(err)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not parse generated CA")
	}

	sess, _ := createMockSession()
	proxy := NewHTTPProxy(sess, "live")
	if err := proxy.ConfigureTLS("127.0.0.1", 0, 0, false, "", certFile, keyFile, "", false); err != nil {
		t.Fatal(err)
	}
	proxy.ConfigureAdaptive(true, 10*time.Minute, 5*time.Second, nil, 0)
	proxy.Start()
	defer func() { _ = proxy.Stop() }()
	select {
	case <-proxy.started:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not start")
	}
	addr := proxy.sniListener.Addr().String()

	type siteResult struct {
		host              string
		category          SiteCategory
		decryptOK         bool
		decryptErr        error
		decryptBusiness   bool
		warmOK            bool
		warmErr           error
		warmBusiness      bool
		passthruOK        bool
		passthruErr       error
		passthroughBizOK  bool
		decryptHandshake  time.Duration
		warmHandshake     time.Duration
		passthruHandshake time.Duration
	}
	results := make([]siteResult, 0, len(hosts))

	for _, host := range hosts {
		// First connection: pays certificate issuance.
		decOK, decErr, decBiz, decHS := liveRequest(t, addr, host, roots, true)
		// Second connection: must be served from the certificate cache.
		warmOK, warmErr, warmBiz, warmHS := liveRequest(t, addr, host, roots, true)
		// Force passthrough for the same host: a client without the proxy CA
		// must still be able to complete the business request.
		proxy.markPassthrough(host, OutcomePassthroughRequested, "measurement: forced passthrough")
		passOK, passErr, passBiz, passHS := liveRequest(t, addr, host, roots, false)

		results = append(results, siteResult{
			host: host, category: classifySite(host),
			decryptOK: decOK, decryptErr: decErr, decryptBusiness: decBiz,
			warmOK: warmOK, warmErr: warmErr, warmBusiness: warmBiz,
			passthruOK: passOK, passthruErr: passErr, passthroughBizOK: passBiz,
			decryptHandshake: decHS, warmHandshake: warmHS, passthruHandshake: passHS,
		})
	}

	perCategory := make(map[SiteCategory]*SiteCategoryStats)
	for _, r := range results {
		item := perCategory[r.category]
		if item == nil {
			item = &SiteCategoryStats{Category: r.category}
			perCategory[r.category] = item
		}
		item.Total++
		if r.decryptOK {
			item.Decrypted++
		}
		if r.decryptErr != nil {
			item.ClientErrors++
		}
		item.AverageHandshake += r.decryptHandshake
	}

	categories := make([]string, 0, len(perCategory))
	for category := range perCategory {
		categories = append(categories, string(category))
	}
	sort.Strings(categories)

	var b strings.Builder
	b.WriteString("\nPer-site results (cold decrypt / warm decrypt / passthrough):\n")
	for _, r := range results {
		b.WriteString(fmt.Sprintf("  %-24s %-7s cold=%v(%s biz=%v hs=%s) warm=%v(%s biz=%v hs=%s) passthrough=%v(%s biz=%v hs=%s)\n",
			r.host, r.category,
			r.decryptOK, errText(r.decryptErr), r.decryptBusiness, r.decryptHandshake.Round(time.Millisecond),
			r.warmOK, errText(r.warmErr), r.warmBusiness, r.warmHandshake.Round(time.Millisecond),
			r.passthruOK, errText(r.passthruErr), r.passthroughBizOK, r.passthruHandshake.Round(time.Millisecond)))
	}

	b.WriteString("\nPer-category summary:\n")
	for _, name := range categories {
		item := perCategory[SiteCategory(name)]
		ratio := 0.0
		if item.Total > 0 {
			ratio = float64(item.Decrypted) / float64(item.Total)
		}
		avg := time.Duration(0)
		if item.Total > 0 {
			avg = item.AverageHandshake / time.Duration(item.Total)
		}
		b.WriteString(fmt.Sprintf("  %-8s total=%d decrypted=%d ratio=%.2f client_errors=%d avg_decrypt_handshake=%s\n",
			item.Category, item.Total, item.Decrypted, ratio, item.ClientErrors, avg.Round(time.Millisecond)))
	}
	b.WriteString("\nProxy stats:\n" + proxy.HTTPSStats().String())

	t.Log(b.String())
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	text := err.Error()
	if len(text) > 60 {
		text = text[:60] + "..."
	}
	return text
}

// liveRequest issues one request through the proxy. trustProxy controls whether
// the client validates the proxy CA (decrypt mode) or not (passthrough mode).
func liveRequest(t *testing.T, addr, host string, roots *x509.CertPool, trustProxy bool) (tlsOK bool, tlsErr error, businessOK bool, handshake time.Duration) {
	t.Helper()

	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, err, false, 0
	}
	defer raw.Close()

	cfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if trustProxy {
		cfg.RootCAs = roots
	}

	conn := tls.Client(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	started := time.Now()
	if err := conn.Handshake(); err != nil {
		return false, err, false, time.Since(started)
	}
	handshake = time.Since(started)

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bettercap-measurement\r\nConnection: close\r\n\r\n", host)
	if _, err := io.WriteString(conn, req); err != nil {
		return true, nil, false, handshake
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodHead})
	if err != nil {
		return true, nil, false, handshake
	}
	defer resp.Body.Close()
	return true, nil, resp.StatusCode > 0, handshake
}
