// Package version exposes build metadata injected at link time via -ldflags
// (see Makefile and .goreleaser.yaml).
package version

// Values are overridden at build time; the defaults identify a non-release build.
var (
	// Version is the semantic version of the build (e.g. "1.2.3").
	Version = "dev"
	// Commit is the short git commit hash the binary was built from.
	Commit = "none"
	// Date is the UTC build timestamp in RFC 3339 format.
	Date = "unknown"
)

// String returns a single-line human-readable version description.
func String() string {
	return Version + " (commit " + Commit + ", built " + Date + ")"
}
