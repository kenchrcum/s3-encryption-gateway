//go:build tools

// Package tools is a dev-only module that tracks tool dependencies via
// go.mod so that `go mod tidy` keeps them pinned and `go install` reproduces
// exactly the same binaries across developer machines and CI.
//
// Tools listed here are never imported at runtime. The `//go:build tools`
// constraint ensures they are excluded from production builds.
//
// V0.6-QA-1: benchstat (statistical benchmark comparison)
// V0.6-QA-2: gremlins (mutation testing — nightly CI)
package tools

import (
	_ "golang.org/x/perf/cmd/benchstat"
	_ "github.com/go-gremlins/gremlins/cmd/gremlins"
)
