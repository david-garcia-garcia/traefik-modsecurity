package traefik_modsecurity

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProductGoTestFiles_HaveZzzPrefix fails when a product *_test.go basename lacks the zzz_ prefix.
func TestProductGoTestFiles_HaveZzzPrefix(t *testing.T) {
	moduleRoot := moduleRootFromTestFile(t)
	walkErr := filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".agents", ".git", "vendor":
				return fs.SkipDir
			default:
				return nil
			}
		}
		name := entry.Name()
		if !strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if strings.HasPrefix(name, "zzz_") {
			return nil
		}
		rel, relErr := filepath.Rel(moduleRoot, path)
		if relErr != nil {
			rel = path
		}
		t.Errorf("%s: product test basename must match zzz_*_test.go", rel)
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
}

// moduleRootFromTestFile walks from this file to the directory that contains go.mod.
func moduleRootFromTestFile(t *testing.T) string {
	t.Helper()
	_, thisFile, _, callerOK := runtime.Caller(0)
	if !callerOK {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above this test file")
		}
		dir = parent
	}
}
