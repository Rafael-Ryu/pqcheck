// Command crypto-analyzer loads the Go module rooted at the given directory and
// prints detected crypto primitive findings as a JSON array on stdout. It is
// invoked as a subprocess by pqcheck's Python Go detector bridge.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Rafael-Ryu/pqcheck/tools/crypto-analyzer/internal/analyzer"
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run is the testable core of main: it returns the process exit code instead of
// calling os.Exit, so the envelope — usage error (2), loader error (1), the
// nil→[] normalisation, and the JSON encoding — is exercised without spawning a
// subprocess. main is then a thin os.Exit(run(...)) shim.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: crypto-analyzer <module-dir>")
		return 2
	}
	findings, err := analyzer.Analyze(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "crypto-analyzer:", err)
		return 1
	}
	if findings == nil {
		findings = []analyzer.Finding{}
	}
	if err := json.NewEncoder(stdout).Encode(findings); err != nil {
		fmt.Fprintln(stderr, "crypto-analyzer:", err)
		return 1
	}
	return 0
}
