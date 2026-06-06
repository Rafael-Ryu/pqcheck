package analyzer

import (
	"os"
	"strings"
	"testing"
)

// resolveEnv collapses a KEY=VALUE slice the way exec would: the last entry for
// a key wins. This is how the `go list` child actually sees the env.
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
		// Soft memory target for the `go list`/compiler grandchildren, which run
		// over attacker-controlled code; the clean-slate env means the parent's
		// GOMEMLIMIT does not reach them unless pinned here.
		"GOMEMLIMIT": goMemLimit,
	}
	for k, v := range want {
		if got := env[k]; got != v {
			t.Errorf("%s = %q, want %q (host value must not win)", k, got, v)
		}
	}
}

// The env is built from a fixed allowlist, not inherited wholesale. A GO* lever
// that hardenedEnv does not explicitly pin (GODEBUG, GOPRIVATE, GOINSECURE,
// GOFIPS140, ...) must not leak through from the host, even though it is not in
// the override list — a clean slate is the only way to guarantee that.
func TestHardenedEnvDropsUnlistedHostVars(t *testing.T) {
	t.Setenv("GODEBUG", "x509sha1=1")
	t.Setenv("GOPRIVATE", "evil.example/*")
	t.Setenv("GOINSECURE", "evil.example/*")
	t.Setenv("GOFIPS140", "off")
	t.Setenv("SECRET_TOKEN", "leak-me")

	env := resolveEnv(hardenedEnv("/scratch", "-mod=readonly"))

	for _, k := range []string{"GODEBUG", "GOPRIVATE", "GOINSECURE", "GOFIPS140", "SECRET_TOKEN"} {
		if v, ok := env[k]; ok {
			t.Errorf("%s leaked from host as %q; the env must be a clean-slate allowlist", k, v)
		}
	}
}

// PATH and HOME carry over so the toolchain resolves and runs; absent host vars
// must not appear as empty entries.
func TestHardenedEnvCarriesOverPathHome(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/home/scan")
	os.Unsetenv("TMPDIR")

	env := resolveEnv(hardenedEnv("/scratch", "-mod=readonly"))

	if env["PATH"] != "/usr/bin" {
		t.Errorf("PATH = %q, want /usr/bin (needed to find the toolchain)", env["PATH"])
	}
	if env["HOME"] != "/home/scan" {
		t.Errorf("HOME = %q, want /home/scan", env["HOME"])
	}
	if _, ok := env["TMPDIR"]; ok {
		t.Error("TMPDIR was unset on the host; it must not appear in the env")
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
