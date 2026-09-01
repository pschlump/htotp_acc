
package main

// Build information.  These are set at link time by the Makefile via
//   go build -ldflags "-X main.GitCommit=... -X main.GitTag=... -X main.BuildDate=..."
// A plain `go build` without those flags gets the defaults below.

var (
	GitCommit string = "not-set (build with make)"
	GitTag    string = "not-set"
	BuildDate string = "not-set"
)
