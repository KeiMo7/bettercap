package https_proxy

import (
	"time"

	"github.com/bettercap/bettercap/v2/modules/http_proxy"
	"github.com/bettercap/bettercap/v2/session"
	"github.com/bettercap/bettercap/v2/tls"

	"github.com/evilsocket/islazy/fs"
	"github.com/evilsocket/islazy/str"
)

type HttpsProxy struct {
	session.SessionModule
	proxy *http_proxy.HTTPProxy
}

func NewHttpsProxy(s *session.Session) *HttpsProxy {
	mod := &HttpsProxy{
		SessionModule: session.NewSessionModule("https.proxy", s),
		proxy:         http_proxy.NewHTTPProxy(s, "https.proxy"),
	}

	mod.AddParam(session.NewIntParameter("https.port",
		"443",
		"HTTPS port to redirect when the proxy is activated."))

	mod.AddParam(session.NewStringParameter("https.proxy.address",
		session.ParamIfaceAddress,
		session.IPv4Validator,
		"Address to bind the HTTPS proxy to."))

	mod.AddParam(session.NewIntParameter("https.proxy.port",
		"8083",
		"Port to bind the HTTPS proxy to."))

	mod.AddParam(session.NewBoolParameter("https.proxy.redirect",
		"true",
		"Enable or disable port redirection with iptables."))

	mod.AddParam(session.NewBoolParameter("https.proxy.sslstrip",
		"false",
		"Enable or disable SSL stripping."))

	mod.AddParam(session.NewBoolParameter("https.proxy.adaptive",
		"false",
		"Automatically pass through connections when the client rejects the proxy CA or certificate pinning is suspected."))

	mod.AddParam(session.NewIntParameter("https.proxy.passthrough.ttl",
		"3600",
		"Seconds to keep a host in adaptive passthrough mode before retrying MITM."))

	mod.AddParam(session.NewIntParameter("https.proxy.upstream.timeout",
		"3000",
		"Milliseconds to wait for the upstream certificate lookup during dynamic issuance."))

	mod.AddParam(session.NewStringParameter("https.proxy.prewarm",
		"",
		"",
		"Comma separated hostnames whose certificates are warmed after startup (bounded by https.proxy.prewarm.max)."))

	mod.AddParam(session.NewIntParameter("https.proxy.prewarm.max",
		"32",
		"Maximum number of hostnames accepted by https.proxy.prewarm."))

	mod.AddParam(session.NewIntParameter("https.proxy.cache.size",
		"2048",
		"Maximum number of dynamically signed certificates kept in memory."))

	mod.AddParam(session.NewIntParameter("https.proxy.cache.ttl",
		"43200",
		"Maximum seconds a dynamically signed certificate is cached; certificate expiry always wins."))

	mod.AddParam(session.NewStringParameter("https.proxy.injectjs",
		"",
		"",
		"URL, path or javascript code to inject into every HTML page."))

	mod.AddParam(session.NewStringParameter("https.proxy.certificate",
		"~/.bettercap-ca.cert.pem",
		"",
		"HTTPS proxy certification authority TLS certificate file."))

	mod.AddParam(session.NewStringParameter("https.proxy.key",
		"~/.bettercap-ca.key.pem",
		"",
		"HTTPS proxy certification authority TLS key file."))

	tls.CertConfigToModule("https.proxy", &mod.SessionModule, tls.DefaultSpoofConfig)

	mod.AddParam(session.NewStringParameter("https.proxy.script",
		"",
		"",
		"Path of a proxy JS script."))

	mod.AddParam(session.NewStringParameter("https.proxy.blacklist", "", "",
		"Comma separated list of hostnames to skip while proxying (wildcard expressions can be used)."))

	mod.AddParam(session.NewStringParameter("https.proxy.whitelist", "", "",
		"Comma separated list of hostnames to proxy if the blacklist is used (wildcard expressions can be used)."))

	mod.AddHandler(session.NewModuleHandler("https.proxy on", "",
		"Start HTTPS proxy.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("https.proxy off", "",
		"Stop HTTPS proxy.",
		func(args []string) error {
			return mod.Stop()
		}))

	mod.AddHandler(session.NewModuleHandler("https.proxy.stats", "[reset]",
		"Show per-site-category TLS decryption, passthrough, client error and certificate cache statistics.",
		func(args []string) error {
			if len(args) > 0 && args[0] == "reset" {
				mod.proxy.ResetHTTPSStats()
			}
			mod.Session.Events.Printf("%s\n", mod.proxy.HTTPSStats().String())
			return nil
		}))

	mod.InitState("stripper")

	return mod
}

func (mod *HttpsProxy) Name() string {
	return "https.proxy"
}

func (mod *HttpsProxy) Description() string {
	return "A full featured HTTPS proxy that can be used to inject malicious contents into webpages, all HTTPS traffic will be redirected to it."
}

func (mod *HttpsProxy) Author() string {
	return "Simone Margaritelli <evilsocket@gmail.com>"
}

func (mod *HttpsProxy) Configure() error {
	var err error
	var address string
	var proxyPort int
	var httpPort int
	var doRedirect bool
	var scriptPath string
	var certFile string
	var keyFile string
	var stripSSL bool
	var jsToInject string
	var whitelist string
	var blacklist string
	var adaptive bool
	var passthroughTTL int
	var upstreamTimeout int
	var prewarm string
	var prewarmMax int
	var cacheSize int
	var cacheTTL int

	if mod.Running() {
		return session.ErrAlreadyStarted(mod.Name())
	} else if err, address = mod.StringParam("https.proxy.address"); err != nil {
		return err
	} else if err, proxyPort = mod.IntParam("https.proxy.port"); err != nil {
		return err
	} else if err, httpPort = mod.IntParam("https.port"); err != nil {
		return err
	} else if err, doRedirect = mod.BoolParam("https.proxy.redirect"); err != nil {
		return err
	} else if err, stripSSL = mod.BoolParam("https.proxy.sslstrip"); err != nil {
		return err
	} else if err, certFile = mod.StringParam("https.proxy.certificate"); err != nil {
		return err
	} else if certFile, err = fs.Expand(certFile); err != nil {
		return err
	} else if err, keyFile = mod.StringParam("https.proxy.key"); err != nil {
		return err
	} else if keyFile, err = fs.Expand(keyFile); err != nil {
		return err
	} else if err, scriptPath = mod.StringParam("https.proxy.script"); err != nil {
		return err
	} else if err, jsToInject = mod.StringParam("https.proxy.injectjs"); err != nil {
		return err
	} else if err, blacklist = mod.StringParam("https.proxy.blacklist"); err != nil {
		return err
	} else if err, whitelist = mod.StringParam("https.proxy.whitelist"); err != nil {
		return err
	} else if err, adaptive = mod.BoolParam("https.proxy.adaptive"); err != nil {
		return err
	} else if err, passthroughTTL = mod.IntParam("https.proxy.passthrough.ttl"); err != nil {
		return err
	} else if err, upstreamTimeout = mod.IntParam("https.proxy.upstream.timeout"); err != nil {
		return err
	} else if err, prewarm = mod.StringParam("https.proxy.prewarm"); err != nil {
		return err
	} else if err, prewarmMax = mod.IntParam("https.proxy.prewarm.max"); err != nil {
		return err
	} else if err, cacheSize = mod.IntParam("https.proxy.cache.size"); err != nil {
		return err
	} else if err, cacheTTL = mod.IntParam("https.proxy.cache.ttl"); err != nil {
		return err
	}

	mod.proxy.Blacklist = str.Comma(blacklist)
	mod.proxy.Whitelist = str.Comma(whitelist)

	if !fs.Exists(certFile) || !fs.Exists(keyFile) {
		cfg, err := tls.CertConfigFromModule("https.proxy", mod.SessionModule)
		if err != nil {
			return err
		}

		mod.Debug("%+v", cfg)
		mod.Info("generating proxy certification authority TLS key to %s", keyFile)
		mod.Info("generating proxy certification authority TLS certificate to %s", certFile)
		if err := tls.Generate(cfg, certFile, keyFile, true); err != nil {
			return err
		}
	} else {
		mod.Info("loading proxy certification authority TLS key from %s", keyFile)
		mod.Info("loading proxy certification authority TLS certificate from %s", certFile)
	}

	error := mod.proxy.ConfigureTLS(address, proxyPort, httpPort, doRedirect, scriptPath, certFile, keyFile, jsToInject,
		stripSSL)
	mod.proxy.ConfigureCertificateCache(cacheSize, time.Duration(cacheTTL)*time.Second)
	mod.proxy.ConfigureAdaptive(
		adaptive,
		time.Duration(passthroughTTL)*time.Second,
		time.Duration(upstreamTimeout)*time.Millisecond,
		str.Comma(prewarm),
		prewarmMax,
	)

	// save stripper to share it with other http(s) proxies
	mod.State.Store("stripper", mod.proxy.Stripper)

	return error
}

func (mod *HttpsProxy) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	return mod.SetRunning(true, func() {
		mod.proxy.Start()
	})
}

func (mod *HttpsProxy) Stop() error {
	mod.State.Store("stripper", nil)
	return mod.SetRunning(false, func() {
		mod.proxy.Stop()
	})
}
