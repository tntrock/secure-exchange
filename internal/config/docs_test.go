package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every SX_ variable the binary reads must be documented in .env.example and both admin manuals.
func TestEnvVarsDocumented(t *testing.T) {
	re := regexp.MustCompile(`"(SX_[A-Z0-9_]+)"`)
	vars := map[string]bool{}
	for _, src := range []string{"config.go", "../../cmd/secure-exchange/main.go"} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			vars[m[1]] = true
		}
	}
	if len(vars) < 20 {
		t.Fatalf("only %d variables found; regexp broken?", len(vars))
	}
	for _, doc := range []string{"../../.env.example", "../../docs/admin-manual.md", "../../docs/admin-manual.en.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for v := range vars {
			if !strings.Contains(string(b), v) {
				t.Errorf("%s missing from %s", v, doc)
			}
		}
	}
}
