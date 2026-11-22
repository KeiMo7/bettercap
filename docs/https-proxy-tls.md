# HTTPS proxy transparency, trust and fallback

## Trust model

A proxy cannot decrypt arbitrary HTTPS traffic and simultaneously present a
certificate signed by the site's public CA. It does not have the site's private
key, and no public CA will issue a certificate for a domain owned by someone
else. Any leaf the proxy mints is therefore signed by a locally generated CA,
and it is trusted only by clients that trust that CA.

Two supported setups:

1. **Install the proxy CA on the client** (recommended when inspection is the
   goal). The dynamic certificate then validates normally and the browser does
   not show a warning.

   ```text
   scripts/install-bettercap-ca.sh ~/.bettercap-ca.cert.pem     # Linux / macOS
   scripts/install-bettercap-ca.ps1 -CertPath C:\Users\me\.bettercap-ca.cert.pem  # Windows, elevated
   ```

2. **Automatic passthrough** for clients you cannot reconfigure (`https.proxy.
   adaptive true`). A client that rejects the proxy CA is detected, the host is
   moved to transparent passthrough for `https.proxy.passthrough.ttl` seconds,
   and the business request keeps working. The first connection in that window
   still fails, because a TLS handshake cannot be replayed on the same TCP
   connection after the certificate has been sent; installing the CA avoids
   that one failure.

Firefox, Java applications, and anything with a private trust store or
certificate pinning may ignore the OS trust store. In adaptive mode those
clients are moved to passthrough instead of staying permanently broken.

## Dynamic certificates

For each new SNI host the proxy:

1. Reads the upstream certificate through the proxy's own dial path (so an
   environment proxy or redirection is honored), with a bounded timeout.
2. Builds the SAN set: the requested host, a wildcard for the host itself, the
   registrable domain, a wildcard for the registrable domain, a wildcard for
   every intermediate label, and every upstream SAN. Public suffix wildcards
   (`*.com`, `*.co.uk`) are never generated.
3. Copies the upstream subject fields for transparency, keeps the leaf lifetime
   within the proxy CA and upstream certificate lifetimes, and issues a
   short-lived ECDSA P-256 leaf signed by the proxy CA.
4. Returns the leaf followed by the proxy CA chain.

The upstream chain is **not** appended to the generated leaf. A leaf signed by
the proxy CA cannot chain through an unrelated public intermediate; doing so
would produce a chain that fails validation. The upstream chain and validation
result are kept for diagnostics and events instead.

A single certificate therefore covers the requested host **and its sibling
subdomains** of the same registrable domain, so the usual burst of requests to
`www`, `static`, `api`, `cdn`, ... does not trigger a signature per hostname.

## Certificate cache

- Keyed by normalized hostname and port.
- Bounded by `https.proxy.cache.size` (default 2048) and
  `https.proxy.cache.ttl` (default 12 hours); the certificate's own expiry
  always wins.
- LRU eviction by last use.
- A wildcard certificate is reused for any host it covers, even on a different
  cache key.
- Concurrent handshakes for the same host share **one** issuance: the others
  wait for the in-flight result instead of generating duplicate keys.
- The cache is dropped whenever the proxy CA changes.
- `https.proxy.stats` reports hits, misses, hit rate, issuances, average
  issuance latency, evictions and expirations.

The cache does not grow without bound: both the entry count and each entry's
lifetime are capped.

## Modes

Default behavior is unchanged: automatic MITM for every intercepted HTTPS
connection. The only change to the default path is that if a certificate
cannot be issued for a host, the connection is passed through transparently
instead of being aborted, and it is recorded as not decrypted.

Enable adaptive mode with:

```text
set https.proxy.adaptive true
https.proxy on
```

Adaptive outcomes, each with a distinct remediation:

| Outcome | Meaning | What to do |
| --- | --- | --- |
| `decrypted` | TLS terminated, request forwarded. | Nothing. |
| `passthrough_sign_failure` | No usable proxy certificate could be issued. | Check the proxy CA; this is a proxy-side problem, not a client error. |
| `passthrough_untrusted_ca` | The client rejected the proxy CA. | Install the CA (`scripts/install-bettercap-ca.*`). |
| `passthrough_name_mismatch` | The presented certificate did not match the requested name. | Inspect the generated SANs for the host. |
| `passthrough_pinning_suspected` | TLS completed, but the client sent no application data on **repeated** connections. | Keep the host in passthrough. |
| `passthrough_requested` | Passthrough requested explicitly. | Nothing. |
| `passthrough_tls_failure` | Another client-side TLS failure. | Inspect the client and the reason text. |
| `upstream_error` | The origin could not be reached. | Network/DNS problem, not a certificate problem. |

### Pinning detection

Pinning is **not** inferred from a failed connection: a failure could be a
network problem. The proxy distinguishes:

- **Handshake completed, then no application data**: the client accepted the
  certificate chain but refused to use the connection. That is the signature of
  an application-layer pinning check (or of a strict security library). This is
  the only condition that raises `passthrough_pinning_suspected`.
- **Handshake failed**: classified by cause as untrusted CA, name mismatch or a
  generic TLS failure.

Because browsers open speculative preconnect sockets that also complete TLS
and close without sending data, one silent connection is not enough. A host is
moved to passthrough only after `silentHandshakeThreshold` (3) consecutive
silent connections; a single real request resets the counter.

A host in passthrough is retried for MITM after `https.proxy.passthrough.ttl`
seconds, so fixing a trust store or a false verdict is not permanent.

## Upstream verification

The origin certificate is validated against the system roots for reporting.

- A verification failure is logged and emitted as
  `https.proxy.upstream-verification`.
- It never aborts forwarding or decryption: transparency is preserved even for
  self-signed or private-CA origins.
- The origin certificate and chain are read with a bounded timeout; a slow
  origin does not stall the first client handshake beyond
  `https.proxy.upstream.timeout`.

## Issuance latency

The first handshake for a new host pays one upstream round trip plus one ECDSA
key generation. Warm handshakes are served from the cache and are
indistinguishable from a direct connection. Issuance latency is exposed through
`https.proxy.stats`.

Common hosts can be warmed after startup:

```text
set https.proxy.prewarm www.example.com,api.example.com
set https.proxy.prewarm.max 32
https.proxy on
```

Prewarming runs in the background, is skipped once the proxy stops, and is
bounded by `https.proxy.prewarm.max`. It never blocks the listener.

## Statistics and measurement

```text
https.proxy.stats
https.proxy.stats reset
```

The report is split by site category (`static`, `api`, `banking`, `other`),
because a single aggregate number hides the expected difference between a
static site, an API that may enforce pinning and a banking application:

```text
window 9s, total 21, decrypted 14 (66.67%), passthrough 7, client errors 0, upstream errors 0
category       total  decrypted  ratio   passthrough  client_err  upstream_err  avg_handshake
api                 3          2   66.67%            1           0             0            1ms
banking             6          4   66.67%            2           0             0            1ms
static             12          8   66.67%            4           0             0            1ms
cert cache: entries=7/2048 hits=7 misses=7 hit_rate=50.00% issued=7 avg_issue=170ms evictions=0 expirations=0 sign_errors=0
```

Each connection also emits `https.proxy.tls-connection` with the host,
category, decrypted flag, outcome, handshake duration and upstream validation
status.

A convenience measurement against real sites is available (opt-in, it uses the
host's network):

```text
BETTERCAP_LIVE_TLS=1 go test ./modules/http_proxy/ -run TestLiveSiteDecryptRatio -v
BETTERCAP_LIVE_TLS=1 BETTERCAP_LIVE_HOSTS=a.example,b.example go test ./modules/http_proxy/ -run TestLiveSiteDecryptRatio -v
```

It reports, per site and per category: cold-handshake success, warm (cached)
handshake latency, passthrough success, business-request success in both modes
and client-visible errors. Run each category separately; a combined ratio is
not meaningful.

## Parameters

| Parameter | Default | Purpose |
| --- | --- | --- |
| `https.proxy.adaptive` | `false` | Learn passthrough hosts after client certificate failures or suspected pinning. |
| `https.proxy.passthrough.ttl` | `3600` | Seconds before a passthrough host is retried for MITM. |
| `https.proxy.upstream.timeout` | `3000` | Milliseconds allowed for upstream certificate lookup. |
| `https.proxy.prewarm` | empty | Comma-separated hosts to issue certificates for shortly after startup. |
| `https.proxy.prewarm.max` | `32` | Hard upper bound for prewarmed hosts. |
| `https.proxy.cache.size` | `2048` | Maximum cached dynamic certificates. |
| `https.proxy.cache.ttl` | `43200` | Maximum cache lifetime in seconds; certificate expiry always wins. |

## Constraints honored

- Certificate issuance and forwarding reuse the existing implementations
  (`tls.SignCertificateForNames`, the goproxy pipeline, the proxy dial path).
- Application payloads are not modified unless injection is explicitly enabled.
- No new dependencies were added (`golang.org/x/net/publicsuffix` is already an
  indirect module dependency).
- Default behavior is preserved; adaptive mode is opt-in.
