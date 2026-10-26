// Package version reads the repo's VERSION and CHANGELOG.md files at runtime
// so the /version endpoint — and therefore the Settings screen — always
// reflects whatever was last committed, with no hardcoded version string to
// forget to bump.
package version

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Info is what GET /version returns.
type Info struct {
	Version   string   `json:"version"`
	Title     string   `json:"title"`   // e.g. "0.1.0 - 2026-10-22"
	Changes   []string `json:"changes"` // bullet lines for this version
	BuiltWith string   `json:"builtWith"`
}

// Read locates VERSION and CHANGELOG.md relative to repoRoot (the directory
// containing core/ and apps/) and parses the changelog entry matching the
// current version.
func Read(repoRoot string) (Info, error) {
	versionBytes, err := os.ReadFile(filepath.Join(repoRoot, "VERSION"))
	if err != nil {
		return Info{}, err
	}
	ver := strings.TrimSpace(string(versionBytes))

	info := Info{
		Version:   ver,
		Title:     ver,
		BuiltWith: "sentrybench-core",
	}

	changelogPath := filepath.Join(repoRoot, "CHANGELOG.md")
	f, err := os.Open(changelogPath)
	if err != nil {
		// No changelog is not fatal — version endpoint still works.
		return info, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inSection := false
	heading := "## [" + ver + "]"
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "## [") {
			if inSection {
				// Reached the next version's section — stop.
				break
			}
			if strings.HasPrefix(line, heading) {
				inSection = true
				info.Title = strings.TrimSpace(strings.TrimPrefix(line, "## "))
				info.Title = strings.Trim(info.Title, "[]")
				continue
			}
			continue
		}
		if inSection {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "- ") {
				info.Changes = append(info.Changes, strings.TrimPrefix(trimmed, "- "))
			}
		}
	}

	return info, nil
}
