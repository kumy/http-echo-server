package version

import (
	"strings"
	"testing"
)

func TestStringContainsAllParts(t *testing.T) {
	s := String()
	for _, part := range []string{Version, Commit, Date} {
		if !strings.Contains(s, part) {
			t.Errorf("String() = %q, missing %q", s, part)
		}
	}
}
