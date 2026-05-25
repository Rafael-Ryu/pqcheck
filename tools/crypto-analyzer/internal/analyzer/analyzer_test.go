package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

// writeModule creates a throwaway Go module under a temp dir and returns its root.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = "module testmod\n\ngo 1.24\n"
	}
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func findingsByAlgo(fs []Finding) map[string]Finding {
	m := make(map[string]Finding, len(fs))
	for _, f := range fs {
		m[f.Algorithm] = f
	}
	return m
}

func TestAnalyzeResolvesStdlibCall(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"crypto/md5\"\n\nfunc main() { md5.New() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	byAlgo := findingsByAlgo(fs)
	md5, ok := byAlgo["MD5"]
	if !ok {
		t.Fatalf("expected MD5 finding, got %+v", fs)
	}
	if md5.Family != "hash" {
		t.Errorf("family = %q, want hash", md5.Family)
	}
	if md5.Line != 5 {
		t.Errorf("line = %d, want 5", md5.Line)
	}
	if md5.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", md5.Confidence)
	}
	if md5.Evidence != "func main() { md5.New() }" {
		t.Errorf("evidence = %q", md5.Evidence)
	}
}

func TestAnalyzeResolvesThroughAlias(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport h \"crypto/sha256\"\n\nfunc main() { h.New() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if _, ok := findingsByAlgo(fs)["SHA-256"]; !ok {
		t.Fatalf("expected SHA-256 via alias, got %+v", fs)
	}
}

func TestAnalyzeNoCryptoEmitsNothing(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hi\") }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestAnalyzeExtractsRSAKeySizeLiteral(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport (\n\"crypto/rsa\"\n\"crypto/rand\"\n)\nfunc main(){ rsa.GenerateKey(rand.Reader, 2048) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	rsa := findingsByAlgo(fs)["RSA"]
	if rsa.KeySize == nil || *rsa.KeySize != 2048 {
		t.Fatalf("key size = %v, want 2048", rsa.KeySize)
	}
}

func TestAnalyzeFoldsRSAKeySizeFromConst(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport (\n\"crypto/rsa\"\n\"crypto/rand\"\n)\nconst bits = 4096\nfunc main(){ rsa.GenerateKey(rand.Reader, bits) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	rsa := findingsByAlgo(fs)["RSA"]
	if rsa.KeySize == nil || *rsa.KeySize != 4096 {
		t.Fatalf("key size = %v, want 4096 (const-folded, not a literal)", rsa.KeySize)
	}
}

func TestAnalyzeExtractsECDSACurve(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport (\n\"crypto/ecdsa\"\n\"crypto/elliptic\"\n\"crypto/rand\"\n)\nfunc main(){ ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	ec := findingsByAlgo(fs)["ECDSA"]
	if ec.Curve != "P-256" {
		t.Fatalf("curve = %q, want P-256", ec.Curve)
	}
}
