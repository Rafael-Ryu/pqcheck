// Command crypto-analyzer loads the Go module rooted at the given directory and
// prints detected crypto primitive findings as a JSON array on stdout. It is
// invoked as a subprocess by pqcheck's Python Go detector bridge.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Rafael-Ryu/pqcheck/tools/crypto-analyzer/internal/analyzer"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: crypto-analyzer <module-dir>")
		os.Exit(2)
	}
	findings, err := analyzer.Analyze(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "crypto-analyzer:", err)
		os.Exit(1)
	}
	if findings == nil {
		findings = []analyzer.Finding{}
	}
	if err := json.NewEncoder(os.Stdout).Encode(findings); err != nil {
		fmt.Fprintln(os.Stderr, "crypto-analyzer:", err)
		os.Exit(1)
	}
}
