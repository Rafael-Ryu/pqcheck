package analyzer

import (
	"fmt"
	"testing"
)

// The design spec enumerates adversarial inputs the analyzer must survive
// without inventing findings or aborting: an import cycle, a missing dependency
// (the "no invention" guarantee), crypto reached through a wrapper, and a large
// module. These complement the hostile-env cases in analyzer_hostile_test.go.

// An import cycle is a load error the type checker records per package; it must
// not abort the whole load nor take down an unrelated package that resolves
// fine. crypto/sha256 in a third, acyclic package must still be found.
func TestAnalyzeImportCycleDoesNotAbortUnrelatedPackage(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"a/a.go": "package a\n\nimport _ \"testmod/b\"\n\nfunc A() {}\n",
		"b/b.go": "package b\n\nimport _ \"testmod/a\"\n\nfunc B() {}\n",
		"clean/clean.go": "package clean\n\nimport \"crypto/sha256\"\n\n" +
			"func C() { sha256.New() }\n",
		"main.go": "package main\n\nimport _ \"testmod/clean\"\n\nfunc main() {}\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("import cycle aborted the load: %v", err)
	}
	if _, ok := findingsByAlgo(fs)["SHA-256"]; !ok {
		t.Fatalf("expected SHA-256 from the acyclic package, got %+v", fs)
	}
}

// A catalogued third-party symbol whose dependency is not resolvable locally
// (no vendor tree, GOPROXY=off so nothing is fetched) must NOT emit: the callee
// never resolves to its real identity, so the catalog cannot match it. This is
// the no-invention guarantee, and the direct contrast to
// TestAnalyzeResolvesVendoredThirdParty, which DOES find BLAKE2B when vendored.
// A stdlib call in the same file still resolves, proving partial resolution.
func TestAnalyzeMissingDepDoesNotInventFinding(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\n" +
			"import (\n\t\"crypto/md5\"\n\t\"golang.org/x/crypto/blake2b\"\n)\n\n" +
			"func main() {\n\tmd5.New()\n\tblake2b.New(32, nil)\n}\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("an unresolvable import must not abort the load: %v", err)
	}
	byAlgo := findingsByAlgo(fs)
	if _, ok := byAlgo["MD5"]; !ok {
		t.Fatalf("expected MD5 (stdlib resolves) despite the missing dep, got %+v", fs)
	}
	if _, ok := byAlgo["BLAKE2B"]; ok {
		t.Fatalf("BLAKE2B emitted for an unresolved dep: catalog must not invent, got %+v", fs)
	}
}

// Crypto called inside a wrapper package resolves to its real callee identity
// wherever the call physically lives, so the wrapper's aes.NewCipher is detected
// even though main only ever calls the wrapper.
func TestAnalyzeResolvesCryptoThroughWrapperPackage(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"cryptohelper/helper.go": "package cryptohelper\n\n" +
			"import (\n\t\"crypto/aes\"\n\t\"crypto/cipher\"\n)\n\n" +
			"func NewAES(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }\n",
		"main.go": "package main\n\n" +
			"import \"testmod/cryptohelper\"\n\n" +
			"func main() { _, _ = cryptohelper.NewAES(make([]byte, 32)) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["AES"]; !ok {
		t.Fatalf("expected AES from the wrapper's aes.NewCipher, got %+v", fs)
	}
}

// A module with many files must be analysed without panicking or dropping
// findings. The bridge owns the memory/RSS backstop (tested there); here the
// only contract is that the analyzer scales to a large input and counts every
// call. Sized to stay fast while still exercising the per-file walk at volume.
func TestAnalyzeHandlesLargeModule(t *testing.T) {
	const n = 120
	files := map[string]string{
		"go.mod":  "module testmod\n\ngo 1.24\n",
		"main.go": "package main\n\nimport _ \"testmod/big\"\n\nfunc main() {}\n",
	}
	for i := range n {
		files[fmt.Sprintf("big/f%d.go", i)] = fmt.Sprintf(
			"package big\n\nimport \"crypto/md5\"\n\nfunc F%d() { md5.New() }\n", i)
	}
	fs, err := Analyze(writeModule(t, files))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var md5Count int
	for _, f := range fs {
		if f.Algorithm == "MD5" {
			md5Count++
		}
	}
	if md5Count != n {
		t.Fatalf("MD5 findings = %d, want %d (one per file)", md5Count, n)
	}
}
