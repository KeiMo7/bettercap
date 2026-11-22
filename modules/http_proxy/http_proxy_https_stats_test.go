package http_proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClassifySite(t *testing.T) {
	tests := []struct {
		host     string
		expected SiteCategory
	}{
		{"www.example.com", SiteCategoryStatic},
		{"static.example.com", SiteCategoryStatic},
		{"cdn.example.com", SiteCategoryStatic},
		{"example.com", SiteCategoryStatic},
		{"api.example.com", SiteCategoryAPI},
		{"api-v2.example.com", SiteCategoryAPI},
		{"my-api.example.com", SiteCategoryAPI},
		{"graphql.example.com", SiteCategoryAPI},
		{"gateway.example.com", SiteCategoryAPI},
		{"online.bank.example", SiteCategoryBanking},
		{"payments.example.com", SiteCategoryBanking},
		{"other.example.com", SiteCategoryOther},
	}

	for _, tt := range tests {
		if got := classifySite(tt.host); got != tt.expected {
			t.Errorf("classifySite(%s) = %s, expected %s", tt.host, got, tt.expected)
		}
	}
}

func TestHTTPSStatsSplitByCategory(t *testing.T) {
	stats := newHTTPSStatsCollector()
	stats.record(SiteCategoryStatic, OutcomeDecrypted, 10*time.Millisecond)
	stats.record(SiteCategoryAPI, OutcomeDecrypted, 20*time.Millisecond)
	stats.record(SiteCategoryAPI, OutcomePassthroughUntrustedCA, 30*time.Millisecond)
	stats.record(SiteCategoryBanking, OutcomePassthroughPinning, 40*time.Millisecond)

	snapshot := stats.snapshot()
	if snapshot.Total != 4 || snapshot.Decrypted != 2 || snapshot.Passthrough != 2 {
		t.Fatalf("unexpected aggregate stats: %+v", snapshot)
	}
	if snapshot.ClientErrors != 2 {
		t.Fatalf("unexpected client error count: %d", snapshot.ClientErrors)
	}

	byCategory := make(map[SiteCategory]SiteCategoryStats)
	for _, item := range snapshot.ByCategory {
		byCategory[item.Category] = item
	}
	if byCategory[SiteCategoryStatic].DecryptRatio != 1 {
		t.Errorf("static decrypt ratio = %f", byCategory[SiteCategoryStatic].DecryptRatio)
	}
	if byCategory[SiteCategoryAPI].DecryptRatio != 0.5 {
		t.Errorf("API decrypt ratio = %f", byCategory[SiteCategoryAPI].DecryptRatio)
	}
	if byCategory[SiteCategoryBanking].DecryptRatio != 0 {
		t.Errorf("banking decrypt ratio = %f", byCategory[SiteCategoryBanking].DecryptRatio)
	}

	output := snapshot.String()
	for _, expected := range []string{"api", "banking", "cert cache", "static"} {
		if !strings.Contains(output, expected) {
			t.Errorf("stats output missing %q:\n%s", expected, output)
		}
	}
}

func TestHTTPSStatsUpstreamErrorsNotClientErrors(t *testing.T) {
	stats := newHTTPSStatsCollector()
	stats.record(SiteCategoryOther, OutcomeUpstreamError, 0)

	snapshot := stats.snapshot()
	if snapshot.UpstreamErrors != 1 {
		t.Fatalf("expected one upstream error: %+v", snapshot)
	}
	if snapshot.ClientErrors != 0 {
		t.Fatalf("an unreachable origin is not a client error: %+v", snapshot)
	}
	if snapshot.Passthrough != 0 {
		t.Fatalf("an unreachable origin is not a passthrough decision: %+v", snapshot)
	}
}

func TestHTTPSStatsSignFailureNotClientError(t *testing.T) {
	stats := newHTTPSStatsCollector()
	stats.record(SiteCategoryOther, OutcomePassthroughSignFailure, 0)

	snapshot := stats.snapshot()
	if snapshot.Passthrough != 1 || snapshot.ClientErrors != 0 {
		t.Fatalf("a signing failure is a proxy-side problem, not a client error: %+v", snapshot)
	}
}

func TestHTTPSStatsReset(t *testing.T) {
	stats := newHTTPSStatsCollector()
	stats.record(SiteCategoryStatic, OutcomeDecrypted, time.Millisecond)
	stats.reset()

	if snapshot := stats.snapshot(); snapshot.Total != 0 {
		t.Fatalf("expected empty stats after reset: %+v", snapshot)
	}
}

func TestClassifyClientHandshakeFailure(t *testing.T) {
	outcome, _ := classifyClientHandshakeFailure(
		errors.New("remote error: tls: unknown certificate authority"),
		"example.com",
		nil,
	)
	if outcome != OutcomePassthroughUntrustedCA {
		t.Fatalf("expected untrusted CA, got %s", outcome)
	}

	cert := &tls.Certificate{
		Leaf: &x509.Certificate{DNSNames: []string{"other.example.com"}},
	}
	outcome, reason := classifyClientHandshakeFailure(
		errors.New("remote error: tls: bad certificate"),
		"example.com",
		cert,
	)
	if outcome != OutcomePassthroughNameMismatch {
		t.Fatalf("expected name mismatch, got %s (%s)", outcome, reason)
	}

	outcome, _ = classifyClientHandshakeFailure(errors.New("remote error: tls: handshake failure"), "example.com", nil)
	if outcome != OutcomePassthroughTLSFailure {
		t.Fatalf("expected generic TLS failure, got %s", outcome)
	}
}

func TestPassthroughOutcomesAreCountedByExplicitCause(t *testing.T) {
	stats := newHTTPSStatsCollector()
	stats.record(SiteCategoryOther, OutcomePassthroughUntrustedCA, 0)
	stats.record(SiteCategoryOther, OutcomePassthroughNameMismatch, 0)
	stats.record(SiteCategoryOther, OutcomePassthroughPinning, 0)
	stats.record(SiteCategoryOther, OutcomePassthroughSignFailure, 0)
	stats.record(SiteCategoryOther, OutcomePassthroughRequested, 0)

	snapshot := stats.snapshot()
	if snapshot.Passthrough != 5 {
		t.Fatalf("expected every passthrough to be counted: %+v", snapshot)
	}
	// Signing failures are proxy-side and requested passthrough is not a
	// failure, so only the three client-caused outcomes count as client errors.
	if snapshot.ClientErrors != 3 {
		t.Fatalf("expected 3 client errors, got %d: %+v", snapshot.ClientErrors, snapshot)
	}
	for _, outcome := range []ConnectionOutcome{
		OutcomePassthroughUntrustedCA, OutcomePassthroughNameMismatch,
		OutcomePassthroughPinning, OutcomePassthroughSignFailure, OutcomePassthroughRequested,
	} {
		if snapshot.ByOutcome[outcome] != 1 {
			t.Errorf("outcome %s was not counted: %+v", outcome, snapshot.ByOutcome)
		}
	}
}

func TestNormalizeDomainListIsBounded(t *testing.T) {
	domains := normalizeDomainList([]string{
		"Example.com", " example.com ", "bad/name", "*.wild.com", "one.example.com",
		"two.example.com", "three.example.com",
	}, 3)

	if len(domains) != 3 {
		t.Fatalf("expected a bounded list of 3, got %v", domains)
	}
	if domains[0] != "example.com" {
		t.Fatalf("expected a normalized and deduplicated first entry, got %v", domains)
	}
	for _, domain := range domains {
		if strings.ContainsAny(domain, "/* ") {
			t.Fatalf("invalid domain leaked into the prewarm list: %q", domain)
		}
	}
}
