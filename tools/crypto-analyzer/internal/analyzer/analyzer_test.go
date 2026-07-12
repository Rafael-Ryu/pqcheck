package analyzer

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestAnalyzeClampsAbsurdRSAKeySize(t *testing.T) {
	// constInt bounds the folded value to a plausible key-size range so an
	// attacker-supplied negative or huge constant cannot flow downstream as a
	// key size. The RSA call must still be reported (detection is by callee),
	// but with no key size. maxKeySize is 1<<20, so 1<<21 is over the bound.
	for name, bits := range map[string]string{
		"negative": "-1",
		"zero":     "0",
		"oversize": "1 << 21",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{
				"main.go": "package main\nimport (\n\"crypto/rsa\"\n\"crypto/rand\"\n)\n" +
					"const bits = " + bits + "\nfunc main(){ rsa.GenerateKey(rand.Reader, bits) }\n",
			})
			fs, err := Analyze(dir)
			if err != nil {
				t.Fatal(err)
			}
			rsa := findingsByAlgo(fs)["RSA"]
			if rsa.Algorithm != "RSA" {
				t.Fatalf("expected an RSA finding, got %+v", rsa)
			}
			if rsa.KeySize != nil {
				t.Fatalf("key size = %d, want nil (absurd constant must not flow)", *rsa.KeySize)
			}
		})
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

func TestAnalyzeNormalizesECDSACurves(t *testing.T) {
	// normalizeCurve maps every crypto/elliptic constructor to the policy
	// vocabulary, not just P-256. Asserting "P-224"/"P-384"/"P-521" (not the
	// raw "P224" etc.) proves the mapping ran for each.
	for ctor, want := range map[string]string{
		"P224": "P-224",
		"P384": "P-384",
		"P521": "P-521",
	} {
		t.Run(ctor, func(t *testing.T) {
			dir := writeModule(t, map[string]string{
				"main.go": "package main\nimport (\n\"crypto/ecdsa\"\n\"crypto/elliptic\"\n\"crypto/rand\"\n)\n" +
					"func main(){ ecdsa.GenerateKey(elliptic." + ctor + "(), rand.Reader) }\n",
			})
			fs, err := Analyze(dir)
			if err != nil {
				t.Fatal(err)
			}
			ec := findingsByAlgo(fs)["ECDSA"]
			if ec.Curve != want {
				t.Fatalf("curve = %q, want %q", ec.Curve, want)
			}
		})
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

// A cipher.Block produced by a `var` declaration (a ValueSpec, not an
// AssignStmt) must still link its mode. `var x = call()` is idiomatic Go and
// common at package scope; missing it silently drops the mode on the algorithm
// finding, under-reporting weak modes (CBC/CFB/ECB).
func TestAnalyzeLinksModeToVarDeclaredBlock(t *testing.T) {
	for name, src := range map[string]string{
		"package-level": "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\n" +
			"var block, _ = aes.NewCipher(make([]byte, 32))\n" +
			"func main(){ _, _ = cipher.NewGCM(block) }\n",
		"function-local": "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\n" +
			"func main(){\nvar block, _ = aes.NewCipher(make([]byte, 32))\n_, _ = cipher.NewGCM(block)\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{"main.go": src})
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
				t.Fatalf("mode = %q, want GCM (use-def linked through var decl)", aesF[0].Mode)
			}
		})
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

// A single-assignment cipher.Block consumed by two *distinct* mode constructors
// (GCM and CBC) cannot be pinned to one mode: which mode a given call site uses
// is not knowable from the call graph. Reporting the first in source order at
// full confidence would silently mask the weak mode (CBC) — exactly the one the
// policy engine most wants to gate. So the block is treated like a branch-
// ambiguous one: no mode, reduced confidence, regardless of source order.
func TestAnalyzeBlockWithTwoDistinctModesIsAmbiguous(t *testing.T) {
	for name, src := range map[string]string{
		"gcm-then-cbc": "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\n" +
			"func main(){\nblock, _ := aes.NewCipher(make([]byte, 32))\niv := make([]byte, 16)\n" +
			"_, _ = cipher.NewGCM(block)\n_ = cipher.NewCBCEncrypter(block, iv)\n}\n",
		"cbc-then-gcm": "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\n" +
			"func main(){\nblock, _ := aes.NewCipher(make([]byte, 32))\niv := make([]byte, 16)\n" +
			"_ = cipher.NewCBCEncrypter(block, iv)\n_, _ = cipher.NewGCM(block)\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{"main.go": src})
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
			if aesF[0].Mode != "" {
				t.Fatalf("mode = %q, want empty: two distinct modes on one block is ambiguous", aesF[0].Mode)
			}
			if aesF[0].Confidence != ambiguousModeConfidence {
				t.Fatalf("confidence = %v, want %v (ambiguous mode)", aesF[0].Confidence, ambiguousModeConfidence)
			}
		})
	}
}

// The same mode used twice on one block (NewCBCEncrypter + NewCBCDecrypter both
// resolve to "CBC") is NOT ambiguous: the mode is unambiguously CBC. Only two
// *distinct* modes trigger the ambiguity path, so this stays cleanly linked.
func TestAnalyzeBlockWithRepeatedSameModeStaysLinked(t *testing.T) {
	src := "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\n" +
		"func main(){\nblock, _ := aes.NewCipher(make([]byte, 32))\niv := make([]byte, 16)\n" +
		"_ = cipher.NewCBCEncrypter(block, iv)\n_ = cipher.NewCBCDecrypter(block, iv)\n}\n"
	dir := writeModule(t, map[string]string{"main.go": src})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	aes := findingsByAlgo(fs)["AES"]
	if aes.Mode != "CBC" {
		t.Fatalf("mode = %q, want CBC (one distinct mode, repeated)", aes.Mode)
	}
	if aes.Confidence != 1.0 {
		t.Fatalf("confidence = %v, want 1.0 (unambiguous mode)", aes.Confidence)
	}
}

// A pathological evidence line (a crypto call after a huge trailing comment) must
// be truncated at the source: the binary writes evidence to stdout, and a multi-
// megabyte line would otherwise flow there unbounded.
func TestAnalyzeBoundsEvidenceLength(t *testing.T) {
	src := "package main\nimport \"crypto/md5\"\nfunc main(){ md5.New() } //" + strings.Repeat("x", 10_000) + "\n"
	dir := writeModule(t, map[string]string{"main.go": src})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	md5 := findingsByAlgo(fs)["MD5"]
	if md5.Algorithm != "MD5" {
		t.Fatalf("expected MD5, got %+v", fs)
	}
	if len(md5.Evidence) > maxEvidenceBytes {
		t.Fatalf("evidence length = %d, want <= %d (bounded)", len(md5.Evidence), maxEvidenceBytes)
	}
}

// The evidence read is capped at maxSourceBytes: a crypto call within the cap
// still gets its line, one past the cap gets none, proving the file is not
// re-read in full.
func TestAnalyzeCapsSourceFileRead(t *testing.T) {
	old := maxSourceBytes
	maxSourceBytes = 80
	defer func() { maxSourceBytes = old }()
	pad := strings.Repeat("// padding line pushing the second call past the byte cap\n", 50)
	src := "package main\nimport \"crypto/md5\"\nfunc near(){ md5.New() }\n" + pad + "func far(){ md5.New() }\n"
	dir := writeModule(t, map[string]string{"main.go": src})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	var withEvidence, withoutEvidence int
	for _, f := range fs {
		if f.Algorithm != "MD5" {
			continue
		}
		if f.Evidence == "" {
			withoutEvidence++
		} else {
			withEvidence++
		}
	}
	if withEvidence != 1 || withoutEvidence != 1 {
		t.Fatalf("want 1 MD5 with evidence (within cap) and 1 without (past cap), got %+v", fs)
	}
}

func TestAnalyzeResolvesMLKEM(t *testing.T) {
	// crypto/mlkem (Go 1.24+) is the only PQC primitive in the catalog. Both
	// GenerateKey768 and GenerateKey1024 must resolve, so a catalog regression
	// dropping either is caught: two calls => two ML-KEM findings.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport \"crypto/mlkem\"\n" +
			"func main(){ _, _ = mlkem.GenerateKey768(); _, _ = mlkem.GenerateKey1024() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The parameter set is baked into the catalog entry (key_size 768/1024)
	// so the policy's parameter-sets approved rule can match — without it the
	// finding falls to default/medium instead of approved/info.
	sizes := map[int]int{}
	for _, f := range fs {
		if f.Algorithm == "ML-KEM" {
			if f.Family != "key-encapsulation" {
				t.Errorf("family = %q, want key-encapsulation", f.Family)
			}
			if f.KeySize == nil {
				t.Errorf("KeySize = nil, want parameter set, finding %+v", f)
				continue
			}
			sizes[*f.KeySize]++
		}
	}
	if sizes[768] != 1 || sizes[1024] != 1 {
		t.Fatalf("ML-KEM parameter sets = %v, want one 768 and one 1024, got %+v", sizes, fs)
	}
}

func TestAnalyzeAmbiguousModeLowersConfidence(t *testing.T) {
	// A cipher.Block assigned across branches cannot be pinned to a single
	// producer, so the mode is left unlinked (TestAnalyzeBranchedBlockHasNoMode)
	// AND the affected findings drop to reduced confidence: we know a mode was
	// applied but not to which cipher. 0.7 is the project's reduced-confidence
	// value (matches python_detector / go tree-sitter).
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
	if len(fs) == 0 {
		t.Fatalf("expected AES and DES findings, got none")
	}
	for _, f := range fs {
		if f.Confidence != 0.7 {
			t.Errorf("%s.Confidence = %v, want 0.7 (ambiguous mode)", f.Algorithm, f.Confidence)
		}
	}
}

func TestAnalyzeLinkedModeKeepsFullConfidence(t *testing.T) {
	// Positive control: a single-assignment block that links cleanly to GCM
	// stays at full confidence — only ambiguity lowers it.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport (\n\"crypto/aes\"\n\"crypto/cipher\"\n)\n" +
			"func main(){\nblock, _ := aes.NewCipher(make([]byte, 32))\n_, _ = cipher.NewGCM(block)\n}\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	aes := findingsByAlgo(fs)["AES"]
	if aes.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0 (cleanly linked)", aes.Confidence)
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

// TestAnalyzeFindingsAreSorted verifies that Analyze returns findings in a
// stable (Path, Line, Column, Algorithm) order regardless of the package
// enumeration order packages.Load produces. The two sub-packages are named so
// that alphabetical path order ("pkga" before "pkgb") is the expected output,
// but a naive implementation that appends in Load-order would sometimes return
// them the other way around (or return them in a non-deterministic order across
// runs/platforms). We also assert that the returned slice is already sorted so
// the test catches any regression without relying on a lucky Load ordering.
func TestAnalyzeFindingsAreSorted(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		// pkga calls MD5 on line 5, pkgb calls SHA-1 on line 5.
		// Alphabetically pkga < pkgb, so the MD5 finding must come first.
		"pkga/a.go": "package pkga\n\nimport \"crypto/md5\"\n\nfunc A() { md5.New() }\n",
		"pkgb/b.go": "package pkgb\n\nimport \"crypto/sha1\"\n\nfunc B() { sha1.New() }\n",
		// A thin main so the module is valid.
		"main.go": "package main\n\nimport (\n\"testmod/pkga\"\n\"testmod/pkgb\"\n)\nfunc main() { pkga.A(); pkgb.B() }\n",
	})

	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// pkga sorts before pkgb by path and both call on line 5, so the MD5
	// finding must precede the SHA-1 one. Assert the exact expected order
	// rather than re-sorting the output and comparing it to itself.
	want := []string{"a.go:MD5", "b.go:SHA-1"}
	if got := findingKeys(fs); !slices.Equal(got, want) {
		t.Errorf("findings not in sorted order: got %v, want %v", got, want)
	}
}

func findingKeys(fs []Finding) []string {
	keys := make([]string, len(fs))
	for i, f := range fs {
		keys[i] = filepath.Base(f.Path) + ":" + f.Algorithm
	}
	return keys
}
