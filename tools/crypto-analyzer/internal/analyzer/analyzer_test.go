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

func TestAnalyzeResolvesEllipticCurveFamily(t *testing.T) {
	// elliptic.PXXX() called bare (not as an ecdsa.GenerateKey argument) is
	// its own call site — the curve object is usable for either ECDSA or
	// ECDH, so it gets the deliberately-ambiguous "elliptic-curve" family
	// and canonical "ECC" rather than guessing which one.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport \"crypto/elliptic\"\n" +
			"func main(){ elliptic.P256(); elliptic.P384(); elliptic.P521() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	curves := map[string]int{}
	for _, f := range fs {
		if f.Algorithm != "ECC" {
			continue
		}
		if f.Family != "elliptic-curve" {
			t.Errorf("family = %q, want elliptic-curve", f.Family)
		}
		curves[f.Curve]++
	}
	if curves["P-256"] != 1 || curves["P-384"] != 1 || curves["P-521"] != 1 {
		t.Fatalf("ECC curves = %v, want one each of P-256/P-384/P-521, got %+v", curves, fs)
	}
}

func TestAnalyzeResolvesCryptoRandAsCSPRNG(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport \"crypto/rand\"\n" +
			"func main(){ _, _ = rand.Int(rand.Reader, nil); _, _ = rand.Prime(rand.Reader, 2048) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range fs {
		if f.Algorithm != "CSPRNG" {
			continue
		}
		if f.Family != "random" {
			t.Errorf("family = %q, want random", f.Family)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("CSPRNG findings = %d, want 2, got %+v", n, fs)
	}
}

func TestAnalyzeResolvesCurve25519ThroughVendor(t *testing.T) {
	// x/crypto is not in the module cache in this test environment, so vendor
	// a minimal stub — same pattern as TestAnalyzeResolvesVendoredThirdParty.
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n\nrequire golang.org/x/crypto v0.0.0\n",
		"vendor/modules.txt": "# golang.org/x/crypto v0.0.0\n" +
			"## explicit; go 1.24\n" +
			"golang.org/x/crypto/curve25519\n",
		"vendor/golang.org/x/crypto/curve25519/curve25519.go": "package curve25519\n\n" +
			"func X25519(scalar, point []byte) ([]byte, error) { return nil, nil }\n",
		"main.go": "package main\n\n" +
			"import \"golang.org/x/crypto/curve25519\"\n\n" +
			"func main() { _, _ = curve25519.X25519(nil, nil) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["X25519"]; !ok {
		t.Fatalf("expected X25519 from vendored curve25519, got %+v", fs)
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

// ---- Method-call detection (typed receivers, no literal package call) ----

func TestAnalyzeResolvesECDHMethodOnPointerReceiver(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"crypto/ecdsa\"\n\n" +
			"func f(pub *ecdsa.PublicKey) { pub.ECDH() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	ecdh, ok := findingsByAlgo(fs)["ECDH"]
	if !ok {
		t.Fatalf("expected ECDH finding, got %+v", fs)
	}
	if ecdh.Family != "key-agreement" {
		t.Errorf("family = %q, want key-agreement", ecdh.Family)
	}
	if ecdh.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0 (go/types resolved)", ecdh.Confidence)
	}
}

func TestAnalyzeResolvesECDHMethodThroughFieldSelector(t *testing.T) {
	// k.PublicKey.ECDH(): the receiver is a field-access chain (embedded
	// ecdsa.PublicKey), pemutil/ssh.go's actual shape in the smallstep/crypto
	// corpus.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"crypto/ecdsa\"\n\n" +
			"func f(k *ecdsa.PrivateKey) { k.PublicKey.ECDH() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["ECDH"]; !ok {
		t.Fatalf("expected ECDH finding, got %+v", fs)
	}
}

func TestAnalyzeResolvesECDHMethodOnEcdhPrivateKey(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"crypto/ecdh\"\n\n" +
			"func f(k *ecdh.PrivateKey, pub *ecdh.PublicKey) { k.ECDH(pub) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["ECDH"]; !ok {
		t.Fatalf("expected ECDH finding, got %+v", fs)
	}
}

func TestAnalyzeUnrelatedECDHMethodDoesNotEmit(t *testing.T) {
	// Same method name, receiver type is not a catalogued one -- the generic
	// method resolution must not false-positive on a same-named method.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\n" +
			"type Foo struct{}\n" +
			"func (f *Foo) ECDH() (int, error) { return 0, nil }\n" +
			"func g(f *Foo) { f.ECDH() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestAnalyzeResolvesYubiKeyGenerateKeyAtReducedConfidence(t *testing.T) {
	// go-piv is not in the module cache in this test environment, so vendor a
	// minimal stub — same pattern as TestAnalyzeResolvesCurve25519ThroughVendor.
	// The real kms/yubikey/yubikey.go in smallstep/crypto carries a
	// `//go:build cgo` tag and is excluded from this module's build entirely
	// under CGO_ENABLED=0 (hardenedEnv), so only the tree-sitter floor
	// actually reaches that file in production; this test exercises the
	// generic method-resolution mechanism in isolation.
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n\nrequire github.com/go-piv/piv-go/v2 v2.6.0\n",
		"vendor/modules.txt": "# github.com/go-piv/piv-go/v2 v2.6.0\n" +
			"## explicit; go 1.24\n" +
			"github.com/go-piv/piv-go/v2/piv\n",
		"vendor/github.com/go-piv/piv-go/v2/piv/piv.go": "package piv\n\n" +
			"type Slot struct{}\n" +
			"type Key struct{ Algorithm int }\n" +
			"type YubiKey struct{}\n" +
			"func (yk *YubiKey) GenerateKey(managementKey []byte, slot Slot, key Key) (any, error) {\n" +
			"\treturn nil, nil\n}\n",
		"main.go": "package main\n\n" +
			"import \"github.com/go-piv/piv-go/v2/piv\"\n\n" +
			"func f(yk *piv.YubiKey) { yk.GenerateKey(nil, piv.Slot{}, piv.Key{}) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	keygen, ok := findingsByAlgo(fs)["KEYGEN"]
	if !ok {
		t.Fatalf("expected KEYGEN finding, got %+v", fs)
	}
	if keygen.Confidence != opaqueMethodConfidence {
		t.Errorf("confidence = %v, want %v (opaque algorithm)", keygen.Confidence, opaqueMethodConfidence)
	}
	if keygen.Family != "signature" {
		t.Errorf("family = %q, want signature", keygen.Family)
	}
}

func TestAnalyzeResolvesHPKEHybridChain(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n\nrequire filippo.io/hpke v0.4.0\n",
		"vendor/modules.txt": "# filippo.io/hpke v0.4.0\n" +
			"## explicit; go 1.24\n" +
			"filippo.io/hpke\n",
		"vendor/filippo.io/hpke/hpke.go": "package hpke\n\n" +
			"type PrivateKey interface{}\n" +
			"type KEM interface{ GenerateKey() (PrivateKey, error) }\n" +
			"type hybridKEM struct{}\n" +
			"func (hybridKEM) GenerateKey() (PrivateKey, error) { return nil, nil }\n" +
			"func MLKEM768X25519() KEM { return hybridKEM{} }\n" +
			"type dhKEM struct{}\n" +
			"func (dhKEM) GenerateKey() (PrivateKey, error) { return nil, nil }\n" +
			"func DHKEM() KEM { return dhKEM{} }\n",
		"main.go": "package main\n\n" +
			"import \"filippo.io/hpke\"\n\n" +
			"func f() { hpke.MLKEM768X25519().GenerateKey() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	hybrid, ok := findingsByAlgo(fs)["X25519MLKEM768"]
	if !ok {
		t.Fatalf("expected X25519MLKEM768 finding, got %+v", fs)
	}
	if hybrid.Family != "key-encapsulation" {
		t.Errorf("family = %q, want key-encapsulation", hybrid.Family)
	}
	if hybrid.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0 (chain fully type-resolved)", hybrid.Confidence)
	}
}

func TestAnalyzeClassicalHPKEKEMDoesNotClaimHybrid(t *testing.T) {
	// Same interface, different constructor: hpke.DHKEM(...).GenerateKey()
	// must not be misclassified as the post-quantum hybrid just because it
	// shares hpke.KEM's GenerateKey method — this is exactly why the hybrid
	// match is chain-shaped rather than a generic KEM.GenerateKey lookup.
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n\nrequire filippo.io/hpke v0.4.0\n",
		"vendor/modules.txt": "# filippo.io/hpke v0.4.0\n" +
			"## explicit; go 1.24\n" +
			"filippo.io/hpke\n",
		"vendor/filippo.io/hpke/hpke.go": "package hpke\n\n" +
			"type PrivateKey interface{}\n" +
			"type KEM interface{ GenerateKey() (PrivateKey, error) }\n" +
			"type dhKEM struct{}\n" +
			"func (dhKEM) GenerateKey() (PrivateKey, error) { return nil, nil }\n" +
			"func DHKEM() KEM { return dhKEM{} }\n",
		"main.go": "package main\n\n" +
			"import \"filippo.io/hpke\"\n\n" +
			"func f() { hpke.DHKEM().GenerateKey() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no findings for classical-only hpke KEM, got %+v", fs)
	}
}

func TestAnalyzeResolvesTLSX25519MLKEM768Constant(t *testing.T) {
	// crypto/tls.X25519MLKEM768 (Go 1.24+) is a CurveID constant, never
	// called -- resolved via TypesInfo.Uses to a *types.Const, not the
	// *types.Func path qualifiedCallee follows for ordinary calls.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"crypto/tls\"\n\n" +
			"func f() *tls.Config {\n" +
			"    return &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}\n" +
			"}\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	hybrid, ok := findingsByAlgo(fs)["X25519MLKEM768"]
	if !ok {
		t.Fatalf("expected X25519MLKEM768 finding, got %+v", fs)
	}
	if hybrid.Family != "key-encapsulation" {
		t.Errorf("family = %q, want key-encapsulation", hybrid.Family)
	}
	if hybrid.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", hybrid.Confidence)
	}
}

// circlHPKEStub is a minimal vendor stand-in for github.com/cloudflare/circl/hpke,
// carrying only the KEM constants and NewSuite signature the analyzer resolves
// against -- the real package pulls in ML-KEM/Kyber implementations this test
// has no need to vendor.
const circlHPKEStub = "package hpke\n\n" +
	"type KEM uint16\n" +
	"type KDF uint16\n" +
	"type AEAD uint16\n" +
	"type Suite struct{}\n\n" +
	"const (\n" +
	"\tKEM_X25519_HKDF_SHA256 KEM = 0x20\n" +
	"\tKEM_X25519_KYBER768_DRAFT00 KEM = 0x30\n" +
	"\tKEM_XWING KEM = 0x647a\n" +
	")\n" +
	"const KDF_HKDF_SHA256 KDF = 0x1\n" +
	"const AEAD_AES256GCM AEAD = 0x2\n\n" +
	"func NewSuite(kemID KEM, kdfID KDF, aeadID AEAD) Suite { return Suite{} }\n"

func TestAnalyzeResolvesCirclHPKEHybridKEMConstants(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n\nrequire github.com/cloudflare/circl v1.5.0\n",
		"vendor/modules.txt": "# github.com/cloudflare/circl v1.5.0\n" +
			"## explicit; go 1.24\n" +
			"github.com/cloudflare/circl/hpke\n",
		"vendor/github.com/cloudflare/circl/hpke/hpke.go": circlHPKEStub,
		"main.go": "package main\n\n" +
			"import \"github.com/cloudflare/circl/hpke\"\n\n" +
			"func f() {\n" +
			"    _ = hpke.KEM_XWING\n" +
			"    _ = hpke.NewSuite(hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)\n" +
			"    _ = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)\n" +
			"}\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	byAlgo := findingsByAlgo(fs)
	if _, ok := byAlgo["X-WING"]; !ok {
		t.Fatalf("expected X-WING finding, got %+v", fs)
	}
	if _, ok := byAlgo["X25519KYBER768-DRAFT"]; !ok {
		t.Fatalf("expected X25519KYBER768-DRAFT finding, got %+v", fs)
	}
	hpkeFindings := 0
	for _, f := range fs {
		if f.Algorithm == "HPKE" {
			hpkeFindings++
		}
	}
	// Exactly one generic HPKE/VULNERABLE finding: the classical-KEM
	// NewSuite call. The hybrid-KEM NewSuite call must not also emit it --
	// that would contradict the precise hybrid finding at the same call site.
	if hpkeFindings != 1 {
		t.Errorf("generic HPKE findings = %d, want 1: %+v", hpkeFindings, fs)
	}
	if len(fs) != 3 {
		t.Errorf("total findings = %d, want 3 (X-WING, X25519KYBER768-DRAFT, HPKE): %+v", len(fs), fs)
	}
}

func TestAnalyzeResolvesMathRandV2VersionedImportPath(t *testing.T) {
	// go/types resolves the call through the type-checked package object, so
	// the qualified callee is built from Pkg().Path() (the literal import
	// path, "math/rand/v2") regardless of the identifier bound at the call
	// site ("rand") -- this engine never had the tree-sitter bug where the
	// resolver bound the "/v2" path segment itself.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"math/rand/v2\"\n\n" +
			"func main() { _ = rand.Int64N(10) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["MATH-RAND"]; !ok {
		t.Fatalf("expected MATH-RAND from math/rand/v2.Int64N, got %+v", fs)
	}
}

func TestAnalyzeResolvesGoContainerRegistrySHA256(t *testing.T) {
	// go-containerregistry's pkg/v1 directory *is* the package "v1" (Go's
	// semantic import versioning never applies to v0/v1, only v2+), so the
	// unaliased import binds "v1" at call sites -- this is a real, non-SIV
	// use of a trailing "/v1" path segment.
	dir := writeModule(t, map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n\nrequire github.com/google/go-containerregistry v0.0.0\n",
		"vendor/modules.txt": "# github.com/google/go-containerregistry v0.0.0\n" +
			"## explicit; go 1.24\n" +
			"github.com/google/go-containerregistry/pkg/v1\n",
		"vendor/github.com/google/go-containerregistry/pkg/v1/hash.go": "package v1\n\n" +
			"import \"io\"\n\n" +
			"type Hash struct{}\n\n" +
			"func SHA256(r io.Reader) (Hash, int64, error) { return Hash{}, 0, nil }\n",
		"main.go": "package main\n\n" +
			"import (\n\t\"strings\"\n\n\tv1 \"github.com/google/go-containerregistry/pkg/v1\"\n)\n\n" +
			"func main() { _, _, _ = v1.SHA256(strings.NewReader(\"x\")) }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["SHA-256"]; !ok {
		t.Fatalf("expected SHA-256 from go-containerregistry pkg/v1.SHA256, got %+v", fs)
	}
}

func TestAnalyzeResolvesRandRandReceiverMethod(t *testing.T) {
	// *rand.Rand method calls resolve generically through methodKey's named-
	// type receiver lookup (same machinery as crypto/ecdsa.PublicKey.ECDH) --
	// no new mechanism needed, just catalog entries for the Rand type's
	// methods alongside the package-level funcs already catalogued.
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\nimport \"math/rand\"\n\n" +
			"func main() { r := rand.New(rand.NewSource(1)); _ = r.Uint32() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingsByAlgo(fs)["MATH-RAND"]; !ok {
		t.Fatalf("expected MATH-RAND from (*rand.Rand).Uint32, got %+v", fs)
	}
}
