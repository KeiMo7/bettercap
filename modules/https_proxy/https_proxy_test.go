package https_proxy

import (
	"strings"
	"testing"

	"github.com/bettercap/bettercap/v2/session"
)

func TestNewHttpsProxyRegistersAdaptiveParameters(t *testing.T) {
	// AddParam registers parameters in the session environment, so a minimal
	// environment-backed session is enough to inspect the registry.
	env, err := session.NewEnvironment("")
	if err != nil {
		t.Fatal(err)
	}
	sess := &session.Session{Env: env}
	sess.Events = session.NewEventPool(false, false)

	mod := NewHttpsProxy(sess)

	params := mod.Parameters()
	for _, name := range []string{
		"https.proxy.adaptive",
		"https.proxy.passthrough.ttl",
		"https.proxy.upstream.timeout",
		"https.proxy.prewarm",
		"https.proxy.prewarm.max",
		"https.proxy.cache.size",
		"https.proxy.cache.ttl",
	} {
		param, found := params[name]
		if !found {
			t.Errorf("expected parameter %s to be registered", name)
			continue
		}
		if param.Description == "" {
			t.Errorf("parameter %s is missing a description", name)
		}
	}

	// Defaults must preserve existing behavior.
	if param := params["https.proxy.adaptive"]; param == nil || param.Value != "false" {
		t.Errorf("https.proxy.adaptive must default to false, got %v", param)
	}

	foundStats := false
	for _, handler := range mod.Handlers() {
		if handler.Name == "https.proxy.stats" {
			foundStats = true
			if !strings.Contains(handler.Description, "category") {
				t.Errorf("stats handler must mention per-category reporting: %s", handler.Description)
			}
		}
	}
	if !foundStats {
		t.Error("expected the https.proxy.stats handler to be registered")
	}
}
