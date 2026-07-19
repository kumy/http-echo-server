// Command http-echo-server echoes HTTP request properties back to clients.
//
// The daemon is not implemented yet: the project is in its specification
// phase (see docs/specification.md). This stub only provides --version so the
// build, release, and packaging pipelines are exercisable end to end.
package main

import (
	"fmt"
	"os"

	"github.com/kumy/http-echo-server/internal/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println("http-echo-server " + version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "http-echo-server "+version.String())
	fmt.Fprintln(os.Stderr, "not implemented yet — see https://kumy.github.io/http-echo-server/specification/")
	os.Exit(1)
}
