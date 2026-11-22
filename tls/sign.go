package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/bettercap/bettercap/v2/log"
	"golang.org/x/net/publicsuffix"
)

const (
	// DefaultUpstreamTimeout bounds the upstream certificate lookup performed
	// for a new dynamic certificate. A slow or unreachable origin must never
	// make the first client handshake hang indefinitely.
	DefaultUpstreamTimeout = 3 * time.Second

	// DefaultCertificateLifetime is the upper bound for a dynamically signed
	// leaf certificate. The effective lifetime is also capped by the proxy CA
	// and by the upstream certificate.
	DefaultCertificateLifetime = 90 * 24 * time.Hour

	// maxDNSNames bounds the number of SANs put in a generated certificate.
	maxDNSNames = 100

	// certificateClockSkew tolerates minor clock differences with clients.
	certificateClockSkew = 5 * time.Minute
)

// UpstreamCertificate is the certificate information observed from the origin
// server. Verification errors are recorded for diagnostics only: an invalid or
// self-signed upstream certificate must not prevent the proxy from signing a
// certificate for the client, and must not abort forwarding.
type UpstreamCertificate struct {
	Leaf             *x509.Certificate
	Chain            []*x509.Certificate
	Verified         bool
	VerificationErr  error
	HandshakeElapsed time.Duration
}

// SignInfo describes how a dynamic certificate was produced. It is used by the
// proxy for latency, SAN and upstream diagnostics.
type SignInfo struct {
	Host             string
	DNSNames         []string
	Upstream         *UpstreamCertificate
	UpstreamFetchErr error
	Elapsed          time.Duration
}

// DialFunc matches the dial functions exposed by the HTTP proxy, so upstream
// certificate discovery honors the same routing (env proxy, redirection, ...)
// as the forwarded traffic itself.
type DialFunc func(network, addr string) (net.Conn, error)

// CertificateErrorKind identifies failures that need different remediation.
// Client-side failures (untrusted CA, pinning, name mismatch) are classified by
// the proxy, since only the proxy can observe the client handshake.
type CertificateErrorKind string

const (
	CertificateErrorInvalidCA     CertificateErrorKind = "invalid_ca"
	CertificateErrorKeyGeneration CertificateErrorKind = "key_generation"
	CertificateErrorSigning       CertificateErrorKind = "signing"
)

// CertificateError keeps the machine readable cause alongside the original
// error so callers can count and explain issuance failures accurately.
type CertificateError struct {
	Kind CertificateErrorKind
	Host string
	Err  error
}

func (e *CertificateError) Error() string {
	if e.Host == "" {
		return fmt.Sprintf("%s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("%s for %s: %v", e.Kind, e.Host, e.Err)
}

func (e *CertificateError) Unwrap() error {
	return e.Err
}

// FetchServerCertificate reads the origin certificate without requiring it to
// validate. The validation result is returned separately and is never used to
// abort certificate issuance.
func FetchServerCertificate(host string, port int, timeout time.Duration) (*UpstreamCertificate, error) {
	return FetchServerCertificateWithDialer(host, port, timeout, nil)
}

// FetchServerCertificateWithDialer uses the proxy's existing dial path when
// one is available, so environment HTTP proxies and custom routing are honored
// for certificate discovery as well as for the actual forwarded request.
func FetchServerCertificateWithDialer(host string, port int, timeout time.Duration, dial DialFunc) (*UpstreamCertificate, error) {
	if timeout <= 0 {
		timeout = DefaultUpstreamTimeout
	}

	started := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	if dial == nil {
		dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		dial = dialer.Dial
	}

	log.Debug("Fetching TLS certificate from %s ...", addr)
	rawConn, err := dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = rawConn.SetDeadline(started.Add(timeout))

	config := &tls.Config{
		InsecureSkipVerify: true, // verification is reported separately, below
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
	}
	conn := tls.Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("upstream returned no certificates")
	}

	upstream := &UpstreamCertificate{
		Leaf:             state.PeerCertificates[0],
		Chain:            state.PeerCertificates,
		HandshakeElapsed: time.Since(started),
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	verifyOptions := x509.VerifyOptions{Intermediates: intermediates}
	if net.ParseIP(host) == nil {
		verifyOptions.DNSName = host
	}
	if _, verifyErr := upstream.Leaf.Verify(verifyOptions); verifyErr != nil {
		upstream.VerificationErr = verifyErr
		log.Debug("upstream certificate validation failed for %s: %s", host, verifyErr)
	} else {
		upstream.Verified = true
	}

	return upstream, nil
}

// CertificateNamesForHost returns the names a transparent leaf should cover.
// The requested host is always present, together with the registrable domain
// (or the apex host) and a wildcard for every parent below the registrable
// domain, so sibling subdomains of the same site can reuse the certificate.
// Upstream SANs are preserved for transparency.
func CertificateNamesForHost(host string, upstream *x509.Certificate) []string {
	names := make([]string, 0, 8)
	seen := make(map[string]struct{})

	add := func(name string) bool {
		name = normalizeDNSName(name)
		if name == "" || len(names) >= maxDNSNames {
			return name != ""
		}
		if isPublicSuffixWildcard(name) {
			return false
		}
		if _, found := seen[name]; found {
			return true
		}
		seen[name] = struct{}{}
		names = append(names, name)
		return true
	}

	host = normalizeDNSName(host)
	if host == "" {
		return names
	}

	// IP literals cannot be wildcarded, they are their own SAN.
	if net.ParseIP(host) != nil {
		return []string{host}
	}

	add(host)
	add("*." + host)

	registrable, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err == nil && registrable != "" {
		if registrable != host {
			add(registrable)
		}
		add("*." + registrable)

		// Cover every label boundary between the requested host and the
		// registrable domain, e.g. "*.api.example.com" for "v1.api.example.com".
		labels := strings.Split(host, ".")
		for i := 1; i < len(labels)-1; i++ {
			parent := strings.Join(labels[i:], ".")
			if parent == registrable {
				break
			}
			add("*." + parent)
		}
	}
	// Internal or single-label hosts only get the wildcard above: no public
	// suffix wildcard is ever invented.

	if upstream != nil {
		for _, name := range upstream.DNSNames {
			add(name)
		}
		if upstream.Subject.CommonName != "" {
			add(upstream.Subject.CommonName)
		}
	}

	return names
}

func isPublicSuffixWildcard(name string) bool {
	if !strings.HasPrefix(name, "*.") {
		return false
	}
	parent := name[2:]
	suffix, _ := publicsuffix.PublicSuffix(parent)
	return strings.EqualFold(suffix, parent)
}

func normalizeDNSName(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	name = strings.ToLower(name)
	if name == "" || len(name) > 253 || strings.ContainsAny(name, "\x00\r\n\t ") {
		return ""
	}
	if strings.HasPrefix(name, "*.") {
		if len(name) <= 2 || strings.Contains(name[2:], "*") {
			return ""
		}
		return name
	}
	if strings.Contains(name, "*") {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
	}
	return name
}

// SignCertificateForHost signs one certificate for the SNI host, deriving SANs
// and subject information from the observed upstream certificate.
func SignCertificateForHost(ca *tls.Certificate, host string, port int) (*tls.Certificate, error) {
	cert, _, err := SignCertificateForHostWithInfo(ca, host, port)
	return cert, err
}

// SignCertificateForHostWithInfo is the observable variant used by the proxy
// for latency and upstream diagnostics.
func SignCertificateForHostWithInfo(ca *tls.Certificate, host string, port int) (*tls.Certificate, *SignInfo, error) {
	started := time.Now()
	info := &SignInfo{Host: host}

	x509ca, err := certificateAuthority(ca)
	if err != nil {
		return nil, info, &CertificateError{Kind: CertificateErrorInvalidCA, Host: host, Err: err}
	}

	upstream, upstreamErr := FetchServerCertificate(host, port, DefaultUpstreamTimeout)
	info.UpstreamFetchErr = upstreamErr
	if upstreamErr == nil {
		info.Upstream = upstream
	} else {
		log.Warning("Could not fetch upstream certificate for %s:%d, signing from SNI only: %s", host, port, upstreamErr)
	}

	var upstreamLeaf *x509.Certificate
	if upstream != nil {
		upstreamLeaf = upstream.Leaf
	}
	names := CertificateNamesForHost(host, upstreamLeaf)
	info.DNSNames = append([]string(nil), names...)

	cert, err := signCertificateForNames(x509ca, ca, host, names, upstreamLeaf)
	if err != nil {
		return nil, info, err
	}
	info.Elapsed = time.Since(started)
	return cert, info, nil
}

// SignCertificateForNames allows a caller to supply an already fetched
// upstream certificate, avoiding a duplicate network round trip.
func SignCertificateForNames(ca *tls.Certificate, host string, names []string, upstream *x509.Certificate) (*tls.Certificate, error) {
	x509ca, err := certificateAuthority(ca)
	if err != nil {
		return nil, &CertificateError{Kind: CertificateErrorInvalidCA, Host: host, Err: err}
	}
	return signCertificateForNames(x509ca, ca, host, names, upstream)
}

func certificateAuthority(ca *tls.Certificate) (*x509.Certificate, error) {
	if ca == nil || len(ca.Certificate) == 0 || ca.PrivateKey == nil {
		return nil, errors.New("missing certificate authority")
	}

	var x509ca *x509.Certificate
	var err error
	if ca.Leaf != nil {
		x509ca = ca.Leaf
	} else if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return nil, err
	}

	if err := validateCertificateAuthority(x509ca); err != nil {
		return nil, err
	}
	return x509ca, nil
}

func validateCertificateAuthority(ca *x509.Certificate) error {
	now := time.Now()
	if !ca.IsCA {
		return errors.New("certificate is not a CA")
	}
	if now.Before(ca.NotBefore) {
		return fmt.Errorf("certificate authority is not valid before %s", ca.NotBefore)
	}
	if now.After(ca.NotAfter) {
		return fmt.Errorf("certificate authority expired at %s", ca.NotAfter)
	}
	return nil
}

func signCertificateForNames(x509ca *x509.Certificate, ca *tls.Certificate, host string, names []string, upstream *x509.Certificate) (*tls.Certificate, error) {
	// ECDSA P-256 keys are generated in microseconds and are supported by every
	// TLS client that matters, which keeps first-handshake issuance latency low.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &CertificateError{Kind: CertificateErrorKeyGeneration, Host: host, Err: err}
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, &CertificateError{Kind: CertificateErrorKeyGeneration, Host: host, Err: err}
	}

	notBefore, notAfter := certificateValidity(x509ca, upstream)
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               certificateSubject(host, upstream),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              make([]string, 0, len(names)),
	}

	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, x509ca, &priv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, &CertificateError{Kind: CertificateErrorSigning, Host: host, Err: err}
	}

	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, &CertificateError{Kind: CertificateErrorSigning, Host: host, Err: err}
	}

	// The leaf is signed by the proxy CA, so the chain must contain that CA (and
	// any configured intermediate). Appending the upstream chain would produce
	// an invalid path: a leaf issued by our CA cannot chain through an unrelated
	// public intermediate. The upstream chain is retained in SignInfo instead.
	chain := make([][]byte, 0, 1+len(ca.Certificate))
	chain = append(chain, derBytes)
	chain = append(chain, ca.Certificate...)

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

func certificateSubject(host string, upstream *x509.Certificate) pkix.Name {
	if upstream != nil {
		// Mirror the origin subject for transparency: an inspection client
		// sees the same organization and common name fields as the real site.
		subject := upstream.Subject
		if subject.CommonName == "" {
			subject.CommonName = host
		}
		return subject
	}

	return pkix.Name{
		Country:            []string{"US"},
		Locality:           []string{"Scottsdale"},
		Organization:       []string{"GoDaddy.com, Inc."},
		OrganizationalUnit: []string{"https://certs.godaddy.com/repository/"},
		CommonName:         host,
	}
}

func certificateValidity(ca *x509.Certificate, upstream *x509.Certificate) (time.Time, time.Time) {
	now := time.Now()
	notBefore := now.Add(-certificateClockSkew)
	notAfter := now.Add(DefaultCertificateLifetime)

	if !ca.NotAfter.IsZero() && ca.NotAfter.Before(notAfter) {
		notAfter = ca.NotAfter
	}
	if upstream != nil && upstream.NotAfter.After(now) && upstream.NotAfter.Before(notAfter) {
		notAfter = upstream.NotAfter
	}
	if !notAfter.After(notBefore) {
		notAfter = notBefore.Add(24 * time.Hour)
	}

	return notBefore, notAfter
}
