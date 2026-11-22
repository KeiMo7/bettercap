package http_proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCertCacheTTL bounds how long a dynamically signed certificate is
	// reused. It is always capped by the certificate's own expiry.
	DefaultCertCacheTTL = 12 * time.Hour
	// DefaultCertCacheMaxEntries bounds memory usage. Certificates are ECDSA
	// leaves of a few KiB, so a few thousand entries stay cheap.
	DefaultCertCacheMaxEntries = 2048
)

type certCacheEntry struct {
	cert      *tls.Certificate
	domain    string
	port      int
	expiresAt time.Time
	lastUsed  time.Time
}

// certFlight is one in-progress issuance shared by every concurrent handshake
// for the same host.
type certFlight struct {
	done     chan struct{}
	cert     *tls.Certificate
	err      error
	hit      bool
	issuedIn time.Duration
}

// CertCacheStats is a snapshot exposed through the https.proxy.stats command.
type CertCacheStats struct {
	Entries              int           `json:"entries"`
	Capacity             int           `json:"capacity"`
	TTL                  time.Duration `json:"ttl"`
	Hits                 uint64        `json:"hits"`
	Misses               uint64        `json:"misses"`
	HitRate              float64       `json:"hit_rate"`
	Insertions           uint64        `json:"insertions"`
	Evictions            uint64        `json:"evictions"`
	Expirations          uint64        `json:"expirations"`
	SignErrors           uint64        `json:"sign_errors"`
	CertificatesIssued   uint64        `json:"certificates_issued"`
	LastIssueDuration    time.Duration `json:"last_issue_duration"`
	TotalIssueDuration   time.Duration `json:"total_issue_duration"`
	AverageIssueDuration time.Duration `json:"average_issue_duration"`
}

type certCache struct {
	mu       sync.Mutex
	entries  map[string]*certCacheEntry
	inflight map[string]*certFlight
	ttl      time.Duration
	capacity int
	now      func() time.Time
	caID     string

	hits               uint64
	misses             uint64
	insertions         uint64
	evictions          uint64
	expirations        uint64
	signErrors         uint64
	certificatesIssued uint64
	lastIssueDuration  time.Duration
	totalIssueDuration time.Duration
}

func newCertCache(capacity int, ttl time.Duration) *certCache {
	if capacity <= 0 {
		capacity = DefaultCertCacheMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultCertCacheTTL
	}
	return &certCache{
		entries:  make(map[string]*certCacheEntry),
		inflight: make(map[string]*certFlight),
		ttl:      ttl,
		capacity: capacity,
		now:      time.Now,
	}
}

var certStore = newCertCache(DefaultCertCacheMaxEntries, DefaultCertCacheTTL)

func keyFor(domain string, port int) string {
	return fmt.Sprintf("%s:%d", normalizeCacheDomain(domain), port)
}

func normalizeCacheDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// getOrCreateCert performs a single certificate lookup/signing operation per
// host. Concurrent handshakes wait on the same in-flight result instead of
// generating duplicate keys and certificates.
func getOrCreateCert(domain string, port int, gen func() (*tls.Certificate, error)) (*tls.Certificate, bool, time.Duration, error) {
	return certStore.getOrCreate(domain, port, gen)
}

func certCacheStats() CertCacheStats {
	return certStore.stats()
}

func resetCertCache() {
	certStore = newCertCache(DefaultCertCacheMaxEntries, DefaultCertCacheTTL)
}

// setCertCacheCA invalidates the cache whenever the proxy CA changes, so
// certificates signed by a previous CA are never served again.
func setCertCacheCA(ca *tls.Certificate) {
	if ca == nil || len(ca.Certificate) == 0 {
		return
	}
	sum := sha256.Sum256(ca.Certificate[0])
	certStore.setCAID(hex.EncodeToString(sum[:]))
}

func (c *certCache) get(domain string, port int) (*tls.Certificate, bool, time.Duration) {
	key := keyFor(domain, port)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	entry := c.lookupLocked(key, domain, port, now)
	if entry == nil {
		c.misses++
		return nil, false, 0
	}

	entry.lastUsed = now
	c.hits++
	return entry.cert, true, entry.expiresAt.Sub(now)
}

func (c *certCache) set(domain string, port int, cert *tls.Certificate) {
	if cert == nil {
		return
	}

	key := keyFor(domain, port)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.putLocked(key, domain, port, cert, now)
}

func (c *certCache) getOrCreate(domain string, port int, gen func() (*tls.Certificate, error)) (*tls.Certificate, bool, time.Duration, error) {
	if gen == nil {
		return nil, false, 0, fmt.Errorf("missing certificate generator")
	}

	key := keyFor(domain, port)
	now := c.now()

	c.mu.Lock()
	if entry := c.lookupLocked(key, domain, port, now); entry != nil {
		entry.lastUsed = now
		c.hits++
		cert := entry.cert
		c.mu.Unlock()
		return cert, true, 0, nil
	}

	if flight, found := c.inflight[key]; found {
		c.mu.Unlock()
		<-flight.done
		return flight.cert, flight.hit, flight.issuedIn, flight.err
	}

	flight := &certFlight{done: make(chan struct{})}
	c.inflight[key] = flight
	c.misses++
	c.mu.Unlock()

	started := time.Now()
	cert, err := gen()
	elapsed := time.Since(started)

	c.mu.Lock()
	flight.cert = cert
	flight.err = err
	flight.issuedIn = elapsed
	if err != nil {
		c.signErrors++
	} else {
		c.certificatesIssued++
		c.lastIssueDuration = elapsed
		c.totalIssueDuration += elapsed
		c.putLocked(key, domain, port, cert, c.now())
	}
	delete(c.inflight, key)
	close(flight.done)
	c.mu.Unlock()

	return cert, false, elapsed, err
}

// lookupLocked returns a live entry for the key, falling back to any cached
// certificate that is valid for the same host (a wildcard issued for a sibling
// subdomain). Expired entries are dropped as they are encountered.
func (c *certCache) lookupLocked(key, domain string, port int, now time.Time) *certCacheEntry {
	if entry, found := c.entries[key]; found {
		if entry.expiresAt.After(now) {
			return entry
		}
		delete(c.entries, key)
		c.expirations++
	}

	var best *certCacheEntry
	for entryKey, entry := range c.entries {
		if entryKey == key || entry.port != port {
			continue
		}
		if !entry.expiresAt.After(now) {
			delete(c.entries, entryKey)
			c.expirations++
			continue
		}
		if entry.cert == nil || entry.cert.Leaf == nil {
			continue
		}
		if err := entry.cert.Leaf.VerifyHostname(domain); err != nil {
			continue
		}
		if best == nil || entry.lastUsed.After(best.lastUsed) {
			best = entry
		}
	}
	return best
}

func (c *certCache) putLocked(key, domain string, port int, cert *tls.Certificate, now time.Time) {
	expiresAt := now.Add(c.ttl)
	if cert.Leaf != nil && !cert.Leaf.NotAfter.IsZero() && cert.Leaf.NotAfter.Before(expiresAt) {
		expiresAt = cert.Leaf.NotAfter
	}
	if !expiresAt.After(now) {
		// A certificate that is already expired is useless to cache; keep the
		// entry only long enough to avoid a tight re-sign loop.
		expiresAt = now.Add(time.Minute)
	}

	if _, exists := c.entries[key]; !exists {
		c.insertions++
		for len(c.entries) >= c.capacity {
			c.evictOldestLocked()
		}
	}

	c.entries[key] = &certCacheEntry{
		cert:      cert,
		domain:    domain,
		port:      port,
		expiresAt: expiresAt,
		lastUsed:  now,
	}
}

func (c *certCache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range c.entries {
		if oldestKey == "" || entry.lastUsed.Before(oldest) {
			oldestKey = key
			oldest = entry.lastUsed
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
		c.evictions++
	}
}

func (c *certCache) stats() CertCacheStats {
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if !entry.expiresAt.After(now) {
			delete(c.entries, key)
			c.expirations++
		}
	}

	total := c.hits + c.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}
	average := time.Duration(0)
	if c.certificatesIssued > 0 {
		average = c.totalIssueDuration / time.Duration(c.certificatesIssued)
	}

	return CertCacheStats{
		Entries:              len(c.entries),
		Capacity:             c.capacity,
		TTL:                  c.ttl,
		Hits:                 c.hits,
		Misses:               c.misses,
		HitRate:              hitRate,
		Insertions:           c.insertions,
		Evictions:            c.evictions,
		Expirations:          c.expirations,
		SignErrors:           c.signErrors,
		CertificatesIssued:   c.certificatesIssued,
		LastIssueDuration:    c.lastIssueDuration,
		TotalIssueDuration:   c.totalIssueDuration,
		AverageIssueDuration: average,
	}
}

func (c *certCache) configure(capacity int, ttl time.Duration) {
	if capacity <= 0 {
		capacity = DefaultCertCacheMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultCertCacheTTL
	}

	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	c.capacity = capacity
	c.ttl = ttl
	for key, entry := range c.entries {
		if maxExpiry := now.Add(ttl); entry.expiresAt.After(maxExpiry) {
			entry.expiresAt = maxExpiry
		}
		if !entry.expiresAt.After(now) {
			delete(c.entries, key)
			c.expirations++
		}
	}
	for len(c.entries) > c.capacity {
		c.evictOldestLocked()
	}
}

func (c *certCache) resetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.hits = 0
	c.misses = 0
	c.insertions = 0
	c.evictions = 0
	c.expirations = 0
	c.signErrors = 0
	c.certificatesIssued = 0
	c.lastIssueDuration = 0
	c.totalIssueDuration = 0
}

func (c *certCache) setCAID(caID string) {
	if caID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.caID == caID {
		return
	}
	c.caID = caID
	c.entries = make(map[string]*certCacheEntry)
}
