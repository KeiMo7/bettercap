package http_proxy

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCertificate(notAfter time.Time) *tls.Certificate {
	return &tls.Certificate{
		Leaf: &x509.Certificate{NotAfter: notAfter},
	}
}

func TestCertCacheTTLAndCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newCertCache(2, time.Hour)
	cache.now = func() time.Time { return now }

	cache.set("example.com", 443, testCertificate(now.Add(24*time.Hour)))
	if cert, hit, _ := cache.get("EXAMPLE.com.", 443); cert == nil || !hit {
		t.Fatal("expected normalized cache hit")
	}

	now = now.Add(2 * time.Hour)
	if cert, hit, _ := cache.get("example.com", 443); cert != nil || hit {
		t.Fatal("expected expired certificate to miss")
	}
	if stats := cache.stats(); stats.Expirations == 0 {
		t.Fatal("expected expiration counter to increase")
	}

	cache.set("one.example.com", 443, testCertificate(now.Add(time.Hour)))
	now = now.Add(time.Minute)
	cache.set("two.example.com", 443, testCertificate(now.Add(time.Hour)))
	now = now.Add(time.Minute)
	cache.set("three.example.com", 443, testCertificate(now.Add(time.Hour)))

	stats := cache.stats()
	if stats.Entries != 2 {
		t.Fatalf("expected bounded cache size 2, got %d", stats.Entries)
	}
	if stats.Evictions == 0 {
		t.Fatal("expected an eviction")
	}
}

func TestCertCacheCoalescesConcurrentIssuance(t *testing.T) {
	cache := newCertCache(10, time.Hour)
	now := time.Now()
	cache.now = func() time.Time { return now }

	var calls int32
	cert := testCertificate(now.Add(time.Hour))
	gen := func() (*tls.Certificate, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(25 * time.Millisecond)
		return cert, nil
	}

	const workers = 24
	results := make(chan *tls.Certificate, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			got, _, _, err := cache.getOrCreate("api.example.com", 443, gen)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			results <- got
		}()
	}
	wg.Wait()
	close(results)

	if calls != 1 {
		t.Fatalf("expected one issuance, got %d", calls)
	}
	for got := range results {
		if got != cert {
			t.Fatal("all waiters must receive the same certificate")
		}
	}

	stats := cache.stats()
	if stats.CertificatesIssued != 1 {
		t.Fatalf("expected one issued certificate, got %d", stats.CertificatesIssued)
	}
	if stats.Misses != 1 {
		t.Fatalf("expected one cache miss for coalesced requests, got %d", stats.Misses)
	}

	if _, hit, _, err := cache.getOrCreate("api.example.com", 443, gen); err != nil {
		t.Fatal(err)
	} else if !hit {
		t.Fatal("expected a subsequent lookup to hit the cache")
	}
	if calls != 1 {
		t.Fatalf("cache hit invoked the generator: %d calls", calls)
	}
}

func TestCertCacheBoundsTTLByCertificateExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newCertCache(10, 24*time.Hour)
	cache.now = func() time.Time { return now }
	cert := testCertificate(now.Add(5 * time.Minute))

	if _, _, _, err := cache.getOrCreate("example.com", 443, func() (*tls.Certificate, error) {
		return cert, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, hit, ttl := cache.get("example.com", 443); !hit || ttl > 5*time.Minute+time.Second {
		t.Fatalf("cache TTL was not bounded by certificate expiry: hit=%v ttl=%s", hit, ttl)
	}

	now = now.Add(10 * time.Minute)
	if got, hit, _ := cache.get("example.com", 443); got != nil || hit {
		t.Fatal("cache entry outlived the certificate")
	}
}

func TestCertCacheReusesCertificateCoveringSiblingSubdomain(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newCertCache(10, time.Hour)
	cache.now = func() time.Time { return now }
	cert := &tls.Certificate{
		Leaf: &x509.Certificate{
			NotAfter: now.Add(time.Hour),
			DNSNames: []string{"api.example.com", "*.example.com"},
		},
	}
	cache.set("api.example.com", 443, cert)

	got, hit, _ := cache.get("www.example.com", 443)
	if !hit || got != cert {
		t.Fatal("expected the wildcard certificate to cover a sibling subdomain")
	}
}

func TestCertCacheResetOnCAChange(t *testing.T) {
	cache := newCertCache(10, time.Hour)
	now := time.Now()
	cache.now = func() time.Time { return now }
	cache.setCAID("first")
	cache.set("example.com", 443, testCertificate(now.Add(time.Hour)))

	cache.setCAID("first")
	if got, hit, _ := cache.get("example.com", 443); got == nil || !hit {
		t.Fatal("setting the same CA must keep cached certificates")
	}

	cache.setCAID("second")
	if got, hit, _ := cache.get("example.com", 443); got != nil || hit {
		t.Fatal("changing the CA must invalidate cached certificates")
	}
}

func TestCertCacheConfigureShrinksAndExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newCertCache(10, time.Hour)
	cache.now = func() time.Time { return now }
	for _, domain := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		cache.set(domain, 443, testCertificate(now.Add(24*time.Hour)))
		now = now.Add(time.Second)
	}

	cache.configure(1, 2*time.Hour)
	stats := cache.stats()
	if stats.Entries != 1 {
		t.Fatalf("expected capacity 1 after reconfigure, got %d", stats.Entries)
	}
	if stats.Capacity != 1 {
		t.Fatalf("expected recorded capacity 1, got %d", stats.Capacity)
	}

	now = now.Add(3 * time.Hour)
	if got, hit, _ := cache.get("a.example.com", 443); got != nil || hit {
		t.Fatal("expected the shortened TTL to expire entries")
	}
}

func TestResetCertCacheDropsEntries(t *testing.T) {
	resetCertCache()
	certStore.set("example.com", 443, testCertificate(time.Now().Add(time.Hour)))
	if _, hit, _ := certStore.get("example.com", 443); !hit {
		t.Fatal("expected entry before reset")
	}
	resetCertCache()
	if _, hit, _ := certStore.get("example.com", 443); hit {
		t.Fatal("expected a fresh cache after reset")
	}
}
