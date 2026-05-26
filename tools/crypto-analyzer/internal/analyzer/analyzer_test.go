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
	// Columns are 0-based to match the tree-sitter and Python detectors (and
	// models.SourceLocation.column, Field(ge=0)). `md5.New()` starts at the
	// 15th rune of "func main() { md5.New() }", so the 0-based column is 14.
	if md5.Column != 14 {
		t.Errorf("column = %d, want 14 (0-based)", md5.Column)
	}
	if md5.EndColumn <= md5.Column {
		t.Errorf("end column = %d, want > start column %d", md5.EndColumn, md5.Column)
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

func TestAnalyzeLinksGCMModeToAES(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\nfunc main(){\nblock, _ := aes.NewCipher(make([]byte, 32))\n_, _ = cipher.NewGCM(block)\n}\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	var aesF []Finding
	for _, f := range fs {
		if f.Algorithm == "AES" {
			aesF = append(aesF, f)
		}
	}
	if len(aesF) != 1 {
		t.Fatalf("want exactly 1 AES finding (no double-count), got %d: %+v", len(aesF), fs)
	}
	if aesF[0].Mode != "GCM" {
		t.Fatalf("mode = %q, want GCM (use-def linked)", aesF[0].Mode)
	}
}

func TestAnalyzeLinksCBCWeakMode(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\nfunc main(){\nblock, _ := aes.NewCipher(make([]byte, 32))\niv := make([]byte, 16)\n_ = cipher.NewCBCEncrypter(block, iv)\n}\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	var aesF []Finding
	for _, f := range fs {
		if f.Algorithm == "AES" {
			aesF = append(aesF, f)
		}
	}
	if len(aesF) != 1 || aesF[0].Mode != "CBC" {
		t.Fatalf("want 1 AES finding with mode CBC, got %+v", fs)
	}
}

func TestAnalyzeAESWithoutModeHasNoMode(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport \"crypto/aes\"\nfunc main(){ aes.NewCipher(make([]byte, 32)) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	aesF := findingsByAlgo(fs)["AES"]
	if aesF.Algorithm != "AES" {
		t.Fatalf("expected AES finding, got %+v", fs)
	}
	if aesF.Mode != "" {
		t.Fatalf("mode = %q, want empty (no mode constructor)", aesF.Mode)
	}
}

// A block variable assigned in more than one branch is ambiguous: the mode must
// not be attached to whichever assignment happened to be recorded last, because
// that algorithm is not necessarily the one the cipher.Block holds at runtime.
func TestAnalyzeBranchedBlockHasNoMode(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n" +
			"import (\n\"crypto/aes\"\n\"crypto/cipher\"\n\"crypto/des\"\n)\n" +
			"func enc(useAes bool, key []byte) {\n" +
			"\tvar block cipher.Block\n" +
			"\tif useAes {\n\t\tblock, _ = aes.NewCipher(key)\n" +
			"\t} else {\n\t\tblock, _ = des.NewCipher(key)\n\t}\n" +
			"\t_, _ = cipher.NewGCM(block)\n}\n" +
			"func main() { enc(true, nil) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	byAlgo := findingsByAlgo(fs)
	if _, ok := byAlgo["AES"]; !ok {
		t.Fatalf("expected AES finding, got %+v", fs)
	}
	if _, ok := byAlgo["DES"]; !ok {
		t.Fatalf("expected DES finding, got %+v", fs)
	}
	for _, f := range fs {
		if f.Mode != "" {
			t.Fatalf("%s.Mode = %q, want empty: block is ambiguous across branches", f.Algorithm, f.Mode)
		}
	}
}

func TestAnalyzeResolvesDotImport(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n" +
			"import (\n. \"crypto/md5\"\n\"fmt\"\n)\n" +
			"func main() { fmt.Println(New()) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["MD5"]; !ok {
		t.Fatalf("expected MD5 via dot-import, got %+v", fs)
	}
}

func TestAnalyzeResolvesVendoredThirdParty(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n\nrequire golang.org/x/crypto v0.0.0\n",
		"vendor/modules.txt": "# golang.org/x/crypto v0.0.0\n" +
			"## explicit; go 1.24\n" +
			"golang.org/x/crypto/blake2b\n",
		"vendor/golang.org/x/crypto/blake2b/blake2b.go": "package blake2b\n\n" +
			"import \"hash\"\n\n" +
			"func New(size int, key []byte) (hash.Hash, error) { return nil, nil }\n",
		"main.go": "package main\n\n" +
			"import \"golang.org/x/crypto/blake2b\"\n\n" +
			"func main() { blake2b.New(32, nil) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["BLAKE2B"]; !ok {
		t.Fatalf("expected BLAKE2B from vendored dep (needs -mod=vendor), got %+v", fs)
	}
}
