package http_proxy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// SiteCategory groups hosts for reporting. A single global decrypt ratio hides
// the expected differences between static sites (almost always decryptable),
// APIs (frequently pinning) and banking applications (rarely decryptable).
type SiteCategory string

const (
	SiteCategoryStatic  SiteCategory = "static"
	SiteCategoryAPI     SiteCategory = "api"
	SiteCategoryBanking SiteCategory = "banking"
	SiteCategoryOther   SiteCategory = "other"
)

// ConnectionOutcome is the terminal state of one handled TLS connection.
type ConnectionOutcome string

const (
	// OutcomeDecrypted: the proxy terminated TLS and forwarded the request.
	OutcomeDecrypted ConnectionOutcome = "decrypted"
	// OutcomePassthroughSignFailure: no usable certificate could be issued.
	OutcomePassthroughSignFailure ConnectionOutcome = "passthrough_sign_failure"
	// OutcomePassthroughUntrustedCA: the client rejected the proxy CA. This is
	// a trust configuration problem, fixed by installing the CA.
	OutcomePassthroughUntrustedCA ConnectionOutcome = "passthrough_untrusted_ca"
	// OutcomePassthroughNameMismatch: the presented certificate did not match
	// the requested name.
	OutcomePassthroughNameMismatch ConnectionOutcome = "passthrough_name_mismatch"
	// OutcomePassthroughPinning: TLS completed but the client sent no
	// application data, the signature of a client-side pinning check.
	OutcomePassthroughPinning ConnectionOutcome = "passthrough_pinning_suspected"
	// OutcomePassthroughRequested: passthrough was explicitly requested (for
	// example by an operator or a measurement), not caused by a failure.
	OutcomePassthroughRequested ConnectionOutcome = "passthrough_requested"
	// OutcomePassthroughTLSFailure: another client-side TLS failure.
	OutcomePassthroughTLSFailure ConnectionOutcome = "passthrough_tls_failure"
	// OutcomeUpstreamError: the origin could not be reached, so neither
	// decryption nor passthrough could deliver the request.
	OutcomeUpstreamError ConnectionOutcome = "upstream_error"
)

/* SiteCategoryStats is the per-category slice of the report. */
type SiteCategoryStats struct {
	Category         SiteCategory  `json:"category"`
	Total            uint64        `json:"total"`
	Decrypted        uint64        `json:"decrypted"`
	Passthrough      uint64        `json:"passthrough"`
	ClientErrors     uint64        `json:"client_errors"`
	UpstreamErrors   uint64        `json:"upstream_errors"`
	DecryptRatio     float64       `json:"decrypt_ratio"`
	AverageHandshake time.Duration `json:"average_handshake"`
}

// HTTPSProxyStats is a point-in-time snapshot for `https.proxy.stats`.
type HTTPSProxyStats struct {
	StartedAt      time.Time                    `json:"started_at"`
	Total          uint64                       `json:"total"`
	Decrypted      uint64                       `json:"decrypted"`
	Passthrough    uint64                       `json:"passthrough"`
	ClientErrors   uint64                       `json:"client_errors"`
	UpstreamErrors uint64                       `json:"upstream_errors"`
	DecryptRatio   float64                      `json:"decrypt_ratio"`
	ByCategory     []SiteCategoryStats          `json:"by_category"`
	ByOutcome      map[ConnectionOutcome]uint64 `json:"by_outcome"`
	CertCache      CertCacheStats               `json:"cert_cache"`
}

type siteCounters struct {
	total            uint64
	decrypted        uint64
	passthrough      uint64
	clientErrors     uint64
	upstreamErrors   uint64
	handshakeTotal   time.Duration
	handshakeSamples uint64
}

type httpsStatsCollector struct {
	mu         sync.Mutex
	startedAt  time.Time
	byCategory map[SiteCategory]*siteCounters
	byOutcome  map[ConnectionOutcome]uint64
}

func newHTTPSStatsCollector() *httpsStatsCollector {
	return &httpsStatsCollector{
		startedAt:  time.Now(),
		byCategory: make(map[SiteCategory]*siteCounters),
		byOutcome:  make(map[ConnectionOutcome]uint64),
	}
}

func (s *httpsStatsCollector) record(category SiteCategory, outcome ConnectionOutcome, handshake time.Duration) {
	if category == "" {
		category = SiteCategoryOther
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	counters := s.byCategory[category]
	if counters == nil {
		counters = &siteCounters{}
		s.byCategory[category] = counters
	}

	counters.total++
	s.byOutcome[outcome]++
	if handshake > 0 {
		counters.handshakeTotal += handshake
		counters.handshakeSamples++
	}

	switch outcome {
	case OutcomeDecrypted:
		counters.decrypted++
	case OutcomeUpstreamError:
		counters.upstreamErrors++
	case OutcomePassthroughSignFailure, OutcomePassthroughUntrustedCA,
		OutcomePassthroughPinning, OutcomePassthroughNameMismatch,
		OutcomePassthroughRequested, OutcomePassthroughTLSFailure:
		counters.passthrough++
		// Signing failures are proxy-side and requested passthrough is not a
		// failure at all; neither counts as a client error.
		if outcome != OutcomePassthroughSignFailure && outcome != OutcomePassthroughRequested {
			counters.clientErrors++
		}
	}
}

func (s *httpsStatsCollector) snapshot() HTTPSProxyStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := HTTPSProxyStats{
		StartedAt:  s.startedAt,
		ByOutcome:  make(map[ConnectionOutcome]uint64, len(s.byOutcome)),
		ByCategory: make([]SiteCategoryStats, 0, len(s.byCategory)),
		CertCache:  certCacheStats(),
	}

	for outcome, count := range s.byOutcome {
		stats.ByOutcome[outcome] = count
	}

	for category, counters := range s.byCategory {
		item := SiteCategoryStats{
			Category:       category,
			Total:          counters.total,
			Decrypted:      counters.decrypted,
			Passthrough:    counters.passthrough,
			ClientErrors:   counters.clientErrors,
			UpstreamErrors: counters.upstreamErrors,
		}
		if counters.total > 0 {
			item.DecryptRatio = float64(counters.decrypted) / float64(counters.total)
		}
		if counters.handshakeSamples > 0 {
			item.AverageHandshake = counters.handshakeTotal / time.Duration(counters.handshakeSamples)
		}

		stats.Total += counters.total
		stats.Decrypted += counters.decrypted
		stats.Passthrough += counters.passthrough
		stats.ClientErrors += counters.clientErrors
		stats.UpstreamErrors += counters.upstreamErrors
		stats.ByCategory = append(stats.ByCategory, item)
	}

	if stats.Total > 0 {
		stats.DecryptRatio = float64(stats.Decrypted) / float64(stats.Total)
	}
	sort.Slice(stats.ByCategory, func(i, j int) bool {
		return stats.ByCategory[i].Category < stats.ByCategory[j].Category
	})

	return stats
}

func (s *httpsStatsCollector) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startedAt = time.Now()
	s.byCategory = make(map[SiteCategory]*siteCounters)
	s.byOutcome = make(map[ConnectionOutcome]uint64)
}

// classifySite is a heuristic used only for reporting. It is deliberately
// conservative and explainable: hostname markers first, shape second.
func classifySite(host string) SiteCategory {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")
	first := ""
	if len(labels) > 0 {
		first = labels[0]
	}

	bankingMarkers := []string{
		"bank", "banking", "finance", "financial", "broker", "brokerage",
		"trading", "wallet", "payment", "payments", "paypal", "stripe",
		"alipay", "wechatpay", "unionpay", "invest", "mortgage", "insurance",
	}
	for _, marker := range bankingMarkers {
		if strings.Contains(host, marker) {
			return SiteCategoryBanking
		}
	}

	apiMarkers := []string{
		"api", "gateway", "graphql", "grpc", "backend", "rest", "webhook",
		"webhooks", "oauth", "auth",
	}
	for _, marker := range apiMarkers {
		if first == marker || strings.HasPrefix(first, marker+"-") ||
			strings.HasPrefix(first, marker+".") || strings.HasSuffix(first, "-"+marker) {
			return SiteCategoryAPI
		}
	}
	if strings.Contains(host, ".api.") || strings.HasPrefix(host, "api.") || strings.Contains(host, "gateway.") {
		return SiteCategoryAPI
	}

	staticMarkers := []string{
		"www", "static", "cdn", "assets", "img", "images", "media",
		"fonts", "docs", "blog", "news",
	}
	for _, marker := range staticMarkers {
		if first == marker || strings.Contains(host, "."+marker+".") {
			return SiteCategoryStatic
		}
	}

	if strings.Count(host, ".") == 1 {
		return SiteCategoryStatic
	}
	return SiteCategoryOther
}

func (s HTTPSProxyStats) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("window %s, total %d, decrypted %d (%.2f%%), passthrough %d, client errors %d, upstream errors %d\n",
		time.Since(s.StartedAt).Round(time.Second),
		s.Total,
		s.Decrypted,
		s.DecryptRatio*100,
		s.Passthrough,
		s.ClientErrors,
		s.UpstreamErrors,
	))
	b.WriteString("category       total  decrypted  ratio   passthrough  client_err  upstream_err  avg_handshake\n")
	for _, item := range s.ByCategory {
		b.WriteString(fmt.Sprintf("%-14s %6d %10d %7.2f%% %12d %11d %13d %14s\n",
			item.Category,
			item.Total,
			item.Decrypted,
			item.DecryptRatio*100,
			item.Passthrough,
			item.ClientErrors,
			item.UpstreamErrors,
			item.AverageHandshake.Round(time.Millisecond),
		))
	}
	b.WriteString(fmt.Sprintf("cert cache: entries=%d/%d hits=%d misses=%d hit_rate=%.2f%% issued=%d avg_issue=%s evictions=%d expirations=%d sign_errors=%d\n",
		s.CertCache.Entries,
		s.CertCache.Capacity,
		s.CertCache.Hits,
		s.CertCache.Misses,
		s.CertCache.HitRate*100,
		s.CertCache.CertificatesIssued,
		s.CertCache.AverageIssueDuration.Round(time.Millisecond),
		s.CertCache.Evictions,
		s.CertCache.Expirations,
		s.CertCache.SignErrors,
	))

	if len(s.ByOutcome) > 0 {
		b.WriteString("outcomes:\n")
		outcomes := make([]string, 0, len(s.ByOutcome))
		for outcome := range s.ByOutcome {
			outcomes = append(outcomes, string(outcome))
		}
		sort.Strings(outcomes)
		for _, outcome := range outcomes {
			b.WriteString(fmt.Sprintf("  %-34s %d\n", outcome, s.ByOutcome[ConnectionOutcome(outcome)]))
		}
	}

	return strings.TrimSuffix(b.String(), "\n")
}
