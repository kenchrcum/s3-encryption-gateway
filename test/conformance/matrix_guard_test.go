//go:build conformance

package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// knownProviderNames is the list of provider names that must NOT appear as
// string literals inside conformance test bodies. Test functions must use
// capability bits to differentiate provider behaviour; naming a provider
// explicitly creates a maintenance burden and defeats the conformance contract.
var knownProviderNames = []string{
	"minio",
	"garage",
	"rustfs",
	"backblaze-b2",
	"aws",
	"wasabi",
	"hetzner",
	"cosmian",
}

// TestConformance_NoProviderNameLiterals walks every .go file in this package
// and fails if any test function body contains a string-literal comparison
// against a known provider name. This is a tier-2 test (conformance build tag)
// that runs as part of the conformance suite.
//
// Provider names are allowed in:
//   - File names (e.g. provider/minio.go).
//   - Comments (lines beginning with //).
//   - The provider package itself (test/provider/).
//   - This self-test file.
func TestConformance_NoProviderNameLiterals(t *testing.T) {
	// Locate the conformance package directory.
	dir, err := findConformanceDir()
	if err != nil {
		t.Skipf("cannot locate conformance directory: %v", err)
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") &&
			!strings.HasSuffix(fi.Name(), "matrix_guard_test.go") &&
			// Skip the helpers file; it references object keys, not provider names.
			!strings.HasSuffix(fi.Name(), "helpers_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse conformance dir: %v", err)
	}

	for _, pkg := range pkgs {
		for filename, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				val := strings.Trim(lit.Value, `"` + "`")
				for _, pname := range knownProviderNames {
					if strings.EqualFold(val, pname) {
						pos := fset.Position(lit.Pos())
						t.Errorf("%s:%d: provider name literal %q in conformance test body — "+
							"use capability bits instead of branching on provider names",
							filepath.Base(filename), pos.Line, val)
					}
				}
				return true
			})
		}
	}
}

// findConformanceDir returns the directory containing the conformance package.
func findConformanceDir() (string, error) {
	// Walk upward from the current working directory until we find
	// test/conformance/ relative to the module root.
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Check common patterns.
	candidates := []string{
		filepath.Join(wd, "test", "conformance"),
		filepath.Join(wd, "..", "test", "conformance"),
		filepath.Join(wd, "..", "..", "test", "conformance"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", os.ErrNotExist
}
