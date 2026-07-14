// skill.go — install the embedded Claude Code skill.
//
// The cel-rule skill (SKILL.md + references) is embedded in the celctl binary,
// so `go install .../celctl@<version>` followed by `celctl skill install`
// delivers both the tool and the skill. Re-running install after upgrading the
// binary updates the skill in place: updating is
//
//	go install github.com/Vincent056/cel-rule-skill/celctl@latest
//	celctl skill install
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

//go:embed all:skill
var skillFS embed.FS

// skillMarkerName marks a directory as managed by `celctl skill install`, so
// re-installs update it without --force while foreign directories are protected.
const skillMarkerName = ".celctl-skill"

func cmdSkill(args []string) int {
	if len(args) == 0 {
		return fail("skill subcommand required: install|status")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "install":
		return skillInstall(rest)
	case "status":
		return skillStatus(rest)
	default:
		return fail("unknown skill subcommand: %s", sub)
	}
}

func defaultSkillDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "skills", "cel-rule")
}

// binaryVersion returns the module version the binary was built from (set by
// `go install .../celctl@vX.Y.Z`), or "devel" for local builds.
func binaryVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		v := bi.Main.Version
		if v != "" && v != "(devel)" {
			return v
		}
	}
	return "devel"
}

func skillInstall(args []string) int {
	fsFlags := newFlags("skill install")
	dir := fsFlags.String("dir", defaultSkillDir(), "directory to install the skill into")
	force := fsFlags.Bool("force", false, "replace a directory (or symlink) not previously installed by celctl")
	fsFlags.Parse(reorderArgs(args))
	if *dir == "" {
		return fail("cannot determine home directory; pass --dir")
	}

	// Decide whether the target is safe to (over)write.
	if info, err := os.Lstat(*dir); err == nil {
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			if !*force {
				return fail("%s is a symlink (likely a repo checkout); rerun with --force to replace it with a managed install", *dir)
			}
			if err := os.Remove(*dir); err != nil {
				return fail("%v", err)
			}
		case info.IsDir():
			if _, err := os.Stat(filepath.Join(*dir, skillMarkerName)); err != nil && !*force {
				if empty, _ := isEmptyDir(*dir); !empty {
					return fail("%s exists and was not installed by celctl; rerun with --force to overwrite", *dir)
				}
			}
		default:
			if !*force {
				return fail("%s exists and is not a directory; rerun with --force", *dir)
			}
			if err := os.Remove(*dir); err != nil {
				return fail("%v", err)
			}
		}
	}

	n, err := writeEmbeddedSkill(*dir)
	if err != nil {
		return fail("%v", err)
	}
	marker := fmt.Sprintf("version: %s\ninstalled: %s\nsource: github.com/Vincent056/cel-rule-skill/celctl\n",
		binaryVersion(), time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(*dir, skillMarkerName), []byte(marker), 0o644); err != nil {
		return fail("%v", err)
	}
	fmt.Printf("installed skill (%d files, version %s) to %s\n", n, binaryVersion(), *dir)
	fmt.Println("restart Claude Code (or start a new session) to pick it up")
	fmt.Println("to update later: go install github.com/Vincent056/cel-rule-skill/celctl@latest && celctl skill install")
	return 0
}

func skillStatus(args []string) int {
	fsFlags := newFlags("skill status")
	dir := fsFlags.String("dir", defaultSkillDir(), "skill directory to inspect")
	fsFlags.Parse(reorderArgs(args))
	fmt.Printf("binary skill version: %s\n", binaryVersion())
	b, err := os.ReadFile(filepath.Join(*dir, skillMarkerName))
	if err != nil {
		fmt.Printf("installed: no managed install at %s (run: celctl skill install)\n", *dir)
		return 1
	}
	fmt.Printf("installed at %s:\n%s", *dir, string(b))
	installed := ""
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "version: "); ok {
			installed = v
		}
	}
	if installed != binaryVersion() {
		fmt.Println("NOTE: installed skill differs from this binary; run `celctl skill install` to update")
		return 1
	}
	fmt.Println("up to date with this binary")
	return 0
}

// writeEmbeddedSkill copies the embedded skill tree into dir, returning the
// number of files written.
func writeEmbeddedSkill(dir string) (int, error) {
	n := 0
	err := fs.WalkDir(skillFS, "skill", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path, "skill")
		rel = strings.TrimPrefix(rel, "/")
		target := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := skillFS.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}

func isEmptyDir(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}
