package analyzer

import (
	"strings"
	"testing"
)

// resolveEnv collapses a KEY=VALUE slice the way exec would: the last entry for
// a key wins. hardenedEnv appends its pins after os.Environ(), so this is how
// the `go list` child actually sees them.
func resolveEnv(entries []string) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		if k, v, ok := strings.Cut(e, "="); ok {
			out[k] = v
		}
	}
	return out
}

func TestHardenedEnvPinsWinOverHostileHost(t *testing.T) {
	// A hostile or misconfigured host env must not re-enable any lever.
	t.Setenv("GOPROXY", "https://evil.example")
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOCACHE", "/host/cache")
	t.Setenv("GOWORK", "/host/go.work")

	env := resolveEnv(hardenedEnv("/scratch", "-mod=readonly"))

	want := map[string]string{
		"GOTOOLCHAIN": "local",
		"CGO_ENABLED": "0",
		"GOFLAGS":     "-mod=readonly",
		"GOWORK":      "off",
		"GOPROXY":     "off",
		"GOSUMDB":     "off",
		"GOENV":       "off",
		"GOCACHE":     "/scratch/cache",
		"GOMODCACHE":  "/scratch/modcache",
		"GOPATH":      "/scratch/gopath",
	}
	for k, v := range want {
		if got := env[k]; got != v {
			t.Errorf("%s = %q, want %q (host value must not win)", k, got, v)
		}
	}
}

func TestModFlagForSelectsVendor(t *testing.T) {
	plain := writeModule(t, map[string]string{
		"main.go": "package main\nfunc main(){}\n",
	})
	if got := modFlagFor(plain); got != "-mod=readonly" {
		t.Errorf("no vendor tree: modFlagFor = %q, want -mod=readonly", got)
	}
	vendored := writeTree(t, map[string]string{
		"go.mod":             "module v\n\ngo 1.24\n",
		"vendor/modules.txt": "",
	})
	if got := modFlagFor(vendored); got != "-mod=vendor" {
		t.Errorf("vendor/modules.txt present: modFlagFor = %q, want -mod=vendor", got)
	}
}
