package dockerhost

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/springledev/keel/runner"
)

// Sources of a discovered ComposeProject.
const (
	// ComposeSourceLabels marks a project found from container labels —
	// authoritative: its paths are exactly what Compose used.
	ComposeSourceLabels = "labels"
	// ComposeSourceScan marks a defined-but-not-running project found by
	// scanning a configured folder with Compose's default filenames.
	ComposeSourceScan = "scan"
	// ComposeSourceRegistered marks a project from a folder the user
	// registered explicitly (a stack that was never started by label).
	ComposeSourceRegistered = "registered"
)

// ComposeBaseFiles are the default compose filenames in Docker's
// documented lookup order: the first one present is the base file.
var ComposeBaseFiles = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// composeOverrideFiles maps a base file to the override files Compose
// merges over it automatically, in merge order.
var composeOverrideFiles = map[string][]string{
	"compose.yaml":        {"compose.override.yaml", "compose.override.yml"},
	"compose.yml":         {"compose.override.yaml", "compose.override.yml"},
	"docker-compose.yaml": {"docker-compose.override.yaml", "docker-compose.override.yml"},
	"docker-compose.yml":  {"docker-compose.override.yaml", "docker-compose.override.yml"},
}

// PickComposeFiles chooses, from the filenames present in one folder,
// the files `docker compose up` would use there: the first base file
// in lookup order, then its override files in merge order. It returns
// nil when the folder has no base file.
func PickComposeFiles(present []string) []string {
	has := map[string]bool{}
	for _, f := range present {
		has[f] = true
	}
	for _, base := range ComposeBaseFiles {
		if !has[base] {
			continue
		}
		out := []string{base}
		for _, o := range composeOverrideFiles[base] {
			if has[o] {
				out = append(out, o)
			}
		}
		return out
	}
	return nil
}

var scanSeq atomic.Uint64

// candidateComposeNames is every filename the scan asks the helper to
// look for.
func candidateComposeNames() []string {
	names := append([]string{}, ComposeBaseFiles...)
	for _, base := range []string{"compose.yaml", "docker-compose.yaml"} {
		names = append(names, composeOverrideFiles[base]...)
	}
	return names
}

// ScanComposeDirs looks for defined-but-not-running compose projects
// under the given folders on host d. A folder counts if it holds a
// compose file itself (the "project" kind) or, with scanChildren, if
// any of its immediate sub-folders does. Files are read through a
// throwaway read-only helper container (no new SSH file access), with
// folder paths and filenames passed as argv, never into the shell
// text. Project names default to the folder name, as Compose does.
// source is stamped on every result (ComposeSourceScan or
// ComposeSourceRegistered).
func ScanComposeDirs(ctx context.Context, r *runner.Runner, d Docker, helperImage string, dirs []string, scanChildren bool, source string) ([]ComposeProject, error) {
	var out []ComposeProject
	for _, dir := range dirs {
		found, err := scanOneComposeDir(ctx, r, d, helperImage, dir, scanChildren)
		if err != nil {
			return nil, fmt.Errorf("scanning %s on Docker host %s for compose projects: %w", dir, d.Name(), err)
		}
		for _, sub := range sortedKeys(found) {
			files := PickComposeFiles(found[sub])
			if files == nil {
				continue
			}
			wd := path.Join(dir, sub)
			p := ComposeProject{
				Name:       strings.ToLower(path.Base(wd)),
				WorkingDir: wd,
				Source:     source,
			}
			for _, f := range files {
				p.ConfigFiles = append(p.ConfigFiles, path.Join(wd, f))
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// scanOneComposeDir returns, per relative sub-folder ("." for dir
// itself), the candidate compose filenames present.
func scanOneComposeDir(ctx context.Context, r *runner.Runner, d Docker, helperImage, dir string, children bool) (map[string][]string, error) {
	helper := fmt.Sprintf("ballast-compose-scan-%d", scanSeq.Add(1))
	depth := "0"
	if children {
		depth = "1"
	}
	script := `cd /data || exit 1
depth=$1; shift
for d in . $( [ "$depth" = 1 ] && ls -d */ 2>/dev/null ); do
  d=${d%/}
  for f in "$@"; do [ -f "$d/$f" ] && printf '%s\n' "$d/$f"; done
done
exit 0`
	args := append([]string{"run", "--rm", "--name", helper, "--network", "none",
		"-v", dir + ":/data:ro", helperImage, "sh", "-c", script, "sh", depth}, candidateComposeNames()...)
	var buf bytes.Buffer
	res, err := r.Run(ctx, nil, &buf, d.Command(nil, args...))
	if err != nil {
		_, _ = r.Run(context.Background(), nil, nil, d.Command(nil, "rm", "-f", helper))
		if hint := Hint(err, res.Stderr); hint != "" {
			return nil, fmt.Errorf("%s: %w", hint, err)
		}
		return nil, err
	}
	found := map[string][]string{}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		sub, file := path.Split(line)
		sub = strings.TrimSuffix(sub, "/")
		found[sub] = append(found[sub], file)
	}
	return found, nil
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// MergeComposeProjects combines discovery results in priority order:
// label-found projects first (authoritative), then registered folders,
// then scanned ones. A later project is dropped when an earlier one
// already has the same name or the same working directory, so a
// running stack is never listed twice.
func MergeComposeProjects(groups ...[]ComposeProject) []ComposeProject {
	names := map[string]bool{}
	dirs := map[string]bool{}
	var out []ComposeProject
	for _, g := range groups {
		for _, p := range g {
			if names[p.Name] || (p.WorkingDir != "" && dirs[p.WorkingDir]) {
				continue
			}
			names[p.Name] = true
			if p.WorkingDir != "" {
				dirs[p.WorkingDir] = true
			}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
