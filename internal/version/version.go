// Package version holds the build version, in one place so the server, the
// client dashboard, and the release tooling cannot drift apart.
package version

// Version is the release version. Override at build time with:
//
//	go build -ldflags="-X github.com/maborak/mabo-tunnel/internal/version.Version=1.2.3"
var Version = "1.0.0"
