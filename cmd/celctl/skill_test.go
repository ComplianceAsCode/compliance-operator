package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded skill contains the expected files and installs/updates cleanly.
func TestSkillInstallAndStatus(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cel-rule")

	if code := skillInstall([]string{"--dir", dir}); code != 0 {
		t.Fatal("fresh install failed")
	}
	for _, f := range []string{"SKILL.md", "references/cel-cookbook.md", "references/examples.md", skillMarkerName} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s after install: %v", f, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if !strings.Contains(string(b), "name: cel-rule") {
		t.Fatal("SKILL.md content wrong")
	}
	// Re-install (the update path) works without --force thanks to the marker.
	if code := skillInstall([]string{"--dir", dir}); code != 0 {
		t.Fatal("re-install (update) should succeed without --force")
	}
	// status: managed install present, version matches binary ("devel" in tests)
	if code := skillStatus([]string{"--dir", dir}); code != 0 {
		t.Fatal("status should report up to date")
	}
}

// A foreign (unmanaged, non-empty) directory is protected unless --force.
func TestSkillInstallProtectsForeignDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cel-rule")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mine.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := skillInstall([]string{"--dir", dir}); code == 0 {
		t.Fatal("should refuse to overwrite a foreign directory without --force")
	}
	if code := skillInstall([]string{"--dir", dir, "--force"}); code != 0 {
		t.Fatal("--force should overwrite")
	}
}

// A symlinked target (repo-checkout style) is replaced only with --force.
func TestSkillInstallReplacesSymlinkWithForce(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "checkout")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "cel-rule")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if code := skillInstall([]string{"--dir", link}); code == 0 {
		t.Fatal("should refuse to replace a symlink without --force")
	}
	if code := skillInstall([]string{"--dir", link, "--force"}); code != 0 {
		t.Fatal("--force should replace the symlink")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("link should now be a real managed directory")
	}
}
