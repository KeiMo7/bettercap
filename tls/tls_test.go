package tls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/bettercap/bettercap/v2/session"
)

func TestCertConfigToModule(t *testing.T) {
	prefix := "test"
	defaults := DefaultLegitConfig

	dummyEnv, err := session.NewEnvironment("")
	if err != nil {
		t.Fatal(err)
	}
	dummySession := &session.Session{Env: dummyEnv}
	m := session.NewSessionModule(prefix, dummySession)

	CertConfigToModule(prefix, &m, defaults)

	// Check if parameters were added
	if len(m.Parameters()) != 6 {
		t.Errorf("expected 6 parameters, got %d", len(m.Parameters()))
	}
}

func TestCertConfigFromModule(t *testing.T) {
	dummyEnv, err := session.NewEnvironment("")
	if err != nil {
		t.Fatal(err)
	}
	dummySession := &session.Session{Env: dummyEnv}
	m := session.NewSessionModule("test", dummySession)
	prefix := "test"

	// Set some parameters
	m.AddParam(session.NewIntParameter(prefix+".certificate.bits", "2048", "dummy desc"))
	m.AddParam(session.NewStringParameter(prefix+".certificate.country", "TestCountry", ".*", "dummy desc"))
	m.AddParam(session.NewStringParameter(prefix+".certificate.locality", "TestLocality", ".*", "dummy desc"))
	m.AddParam(session.NewStringParameter(prefix+".certificate.organization", "TestOrg", ".*", "dummy desc"))
	m.AddParam(session.NewStringParameter(prefix+".certificate.organizationalunit", "TestUnit", ".*", "dummy desc"))
	m.AddParam(session.NewStringParameter(prefix+".certificate.commonname", "TestCN", ".*", "dummy desc"))

	cfg, err := CertConfigFromModule(prefix, m)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if cfg.Bits != 2048 || cfg.Country != "TestCountry" || cfg.Locality != "TestLocality" ||
		cfg.Organization != "TestOrg" || cfg.OrganizationalUnit != "TestUnit" || cfg.CommonName != "TestCN" {
		t.Error("config not parsed correctly")
	}
}

func TestCreateCertificate(t *testing.T) {
	cfg := DefaultLegitConfig
	cfg.Bits = 1024 // smaller for test

	priv, certBytes, err := CreateCertificate(cfg, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if priv == nil {
		t.Error("private key is nil")
	}
	if len(certBytes) == 0 {
		t.Error("cert bytes empty")
	}

	// Parse to verify
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Errorf("could not parse cert: %v", err)
	}
	if cert.Subject.CommonName != cfg.CommonName {
		t.Errorf("common name mismatch: %s != %s", cert.Subject.CommonName, cfg.CommonName)
	}
	if !cert.IsCA {
		t.Error("not CA")
	}
}

func TestGenerate(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "tlstest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "test.cert")
	keyPath := filepath.Join(tempDir, "test.key")

	cfg := DefaultLegitConfig
	cfg.Bits = 1024

	err = Generate(cfg, certPath, keyPath, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check files exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("cert file not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("key file not created")
	}

	// Load and verify
	certBytes, _ := ioutil.ReadFile(certPath)
	keyBytes, _ := ioutil.ReadFile(keyPath)

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Error("invalid cert PEM")
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Error("invalid key PEM")
	}

	priv, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Errorf("invalid private key: %v", err)
	}
	if priv.N.BitLen() != 1024 {
		t.Errorf("key bits mismatch: %d", priv.N.BitLen())
	}
}

func testCA(t *testing.T) *tls.Certificate {
	t.Helper()

	cfg := DefaultLegitConfig
	cfg.Bits = 2048
	priv, certBytes, err := CreateCertificate(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

func containsName(names []string, expected string) bool {
	for _, name := range names {
		if name == expected {
			return true
		}
	}
	return false
}

func pkixName(commonName string) pkix.Name {
	return pkix.Name{CommonName: commonName}
}

func TestCertificateNamesForHostIncludesWildcardAndUpstreamSANs(t *testing.T) {
	upstream := &x509.Certificate{
		DNSNames: []string{"api.example.com", "*.cdn.example.net", "example.org"},
		Subject:  pkixName("api.example.com"),
	}

	names := CertificateNamesForHost("api.example.com", upstream)
	for _, expected := range []string{
		"api.example.com",
		"example.com",
		"*.example.com",
		"*.api.example.com",
		"*.cdn.example.net",
		"example.org",
	} {
		if !containsName(names, expected) {
			t.Errorf("expected %s in %v", expected, names)
		}
	}
	if containsName(names, "*.com") {
		t.Errorf("must not create a public suffix wildcard: %v", names)
	}
}

func TestCertificateNamesForHostCoversSiblingSubdomains(t *testing.T) {
	// A certificate issued for one deep subdomain must also be usable for its
	// siblings, so a single handshake covers the rest of the site's traffic.
	names := CertificateNamesForHost("v1.api.example.co.uk", nil)
	for _, expected := range []string{
		"v1.api.example.co.uk",
		"example.co.uk",
		"*.example.co.uk",
		"*.api.example.co.uk",
	} {
		if !containsName(names, expected) {
			t.Errorf("expected %s in %v", expected, names)
		}
	}
	if containsName(names, "*.co.uk") {
		t.Errorf("must not create a public suffix wildcard: %v", names)
	}
}

func TestCertificateNamesForHostCoalescesIntoOneCertificate(t *testing.T) {
	// One given certificate must satisfy the requested hostname and all sibling
	// subdomains of its registrable domain.
	names := CertificateNamesForHost("www.example.com", nil)

	cfg := DefaultLegitConfig
	cfg.Bits = 2048
	ca := testCA(t)
	cert, err := SignCertificateForNames(ca, "www.example.com", names, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"www.example.com", "api.example.com", "cdn.example.com"} {
		if err := cert.Leaf.VerifyHostname(host); err != nil {
			t.Errorf("certificate does not cover %s: %v", host, err)
		}
	}
	if err := cert.Leaf.VerifyHostname("example.org"); err == nil {
		t.Error("certificate must not cover unrelated domains")
	}
}

func TestCertificateNamesForHostRejectsInvalidNames(t *testing.T) {
	upstream := &x509.Certificate{
		DNSNames: []string{"bad\nname.example.com", "*.*.example.com", ""},
	}
	names := CertificateNamesForHost("www.example.com", upstream)
	for _, name := range names {
		if name == "bad\nname.example.com" || name == "*.*.example.com" || name == "" {
			t.Errorf("invalid SAN leaked into certificate names: %q", name)
		}
	}
}

func TestCertificateNamesForIP(t *testing.T) {
	names := CertificateNamesForHost("192.0.2.10", nil)
	if !reflect.DeepEqual(names, []string{"192.0.2.10"}) {
		t.Fatalf("unexpected IP names: %v", names)
	}
	if net.ParseIP(names[0]) == nil {
		t.Fatalf("expected an IP SAN, got %v", names)
	}
}

func TestSignCertificateForNamesBuildsVerifiableChain(t *testing.T) {
	ca := testCA(t)
	upstream := &x509.Certificate{
		DNSNames: []string{"api.example.com"},
		Subject:  pkixName("api.example.com"),
		NotAfter: ca.Leaf.NotAfter.Add(-time.Hour),
	}
	names := CertificateNamesForHost("api.example.com", upstream)
	cert, err := SignCertificateForNames(ca, "api.example.com", names, upstream)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		t.Fatal("missing parsed leaf")
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("expected leaf and CA in chain, got %d certificates", len(cert.Certificate))
	}
	if err := cert.Leaf.VerifyHostname("api.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname("v1.api.example.com"); err != nil {
		t.Fatalf("wildcard did not cover subdomain: %v", err)
	}
	if cert.Leaf.Subject.CommonName != "api.example.com" {
		t.Errorf("upstream subject was not preserved: %s", cert.Leaf.Subject.CommonName)
	}
	if cert.Leaf.NotAfter.After(upstream.NotAfter) {
		t.Errorf("leaf outlived the upstream certificate: %s > %s", cert.Leaf.NotAfter, upstream.NotAfter)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Leaf)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "api.example.com",
		Roots:   roots,
	}); err != nil {
		t.Fatalf("signed certificate did not verify with the CA: %v", err)
	}
}

func TestSignCertificateDoesNotChainThroughUpstream(t *testing.T) {
	// The upstream chain belongs to a different trust hierarchy and must never
	// be appended to a leaf signed by the proxy CA.
	ca := testCA(t)
	upstreamServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer upstreamServer.Close()

	upstreamLeaf := upstreamServer.Certificate()
	cert, err := SignCertificateForNames(ca, "example.com", []string{"example.com"}, upstreamLeaf)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != len(ca.Certificate)+1 {
		t.Fatalf("chain must be exactly leaf + proxy CA, got %d certificates", len(cert.Certificate))
	}
	if !bytes.Equal(cert.Certificate[1], ca.Certificate[0]) {
		t.Fatal("second chain element must be the proxy CA")
	}
}

func TestCertificateAuthorityMustBeValid(t *testing.T) {
	ca := testCA(t)
	ca.Leaf.NotAfter = time.Now().Add(-time.Hour)

	if _, err := SignCertificateForNames(ca, "example.com", []string{"example.com"}, nil); err == nil {
		t.Fatal("expected an expired CA to be rejected")
	}
}

func TestFetchServerCertificateRecordsVerificationFailureWithoutAborting(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	port := server.Listener.Addr().(*net.TCPAddr).Port
	dial := func(network, addr string) (net.Conn, error) {
		return net.Dial(network, server.Listener.Addr().String())
	}
	upstream, err := FetchServerCertificateWithDialer("example.com", port, time.Second, dial)
	if err != nil {
		t.Fatalf("certificate discovery should continue despite validation failure: %v", err)
	}
	if upstream.Leaf == nil {
		t.Fatal("missing upstream leaf")
	}
	if upstream.Verified {
		t.Fatal("httptest's private CA must not verify against the system roots")
	}
	if upstream.VerificationErr == nil {
		t.Fatal("expected the verification failure to be recorded")
	}
}
