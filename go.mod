module github.com/jchirayath/remotehound

go 1.26.0

// ONE external module, by design (docs/ARCHITECTURE.md §3.4, ADR-0002):
// golang.org/x/crypto for the embedded SSH tunnel server. ci/guards.sh fails
// the build if anything else is added here.
require golang.org/x/crypto v0.57.0
