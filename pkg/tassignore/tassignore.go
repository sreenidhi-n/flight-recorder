// Package tassignore implements .tassignore file parsing and path matching.
// The syntax is compatible with .gitignore: glob patterns, directory suffixes,
// negation with !, and # comments. Use it to exclude files and directories
// from TASS capability scanning.
package tassignore

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const filename = ".tassignore"

// pattern holds a parsed ignore rule.
type pattern struct {
	raw     string // original pattern text
	negated bool   // true for "!pattern" lines
	dirOnly bool   // true when pattern ends with "/"
	glob    string // the actual glob to match (without ! and trailing /)
}

// Matcher determines whether a given file path should be excluded from scanning.
type Matcher struct {
	patterns []pattern
}

// Load reads .tassignore from the given repo root.
// If the file does not exist, an empty Matcher (nothing ignored) is returned.
func Load(repoRoot string) (*Matcher, error) {
	p := filepath.Join(repoRoot, filename)
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return &Matcher{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pats []pattern
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if pat, ok := parseLine(line); ok {
			pats = append(pats, pat)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &Matcher{patterns: pats}, nil
}

// LoadBytes parses .tassignore content from raw bytes (useful for content
// fetched via GitHub API without writing to disk).
func LoadBytes(data []byte) *Matcher {
	var pats []pattern
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if pat, ok := parseLine(scanner.Text()); ok {
			pats = append(pats, pat)
		}
	}
	return &Matcher{patterns: pats}
}

// ShouldIgnore reports whether the given path (relative to the repo root)
// should be excluded from scanning.
// Patterns are evaluated in order. Later patterns override earlier ones.
// A negation pattern "!foo" un-ignores a path matched by an earlier rule.
func (m *Matcher) ShouldIgnore(filePath string) bool {
	// Normalise to forward slashes regardless of OS.
	filePath = filepath.ToSlash(filePath)
	// Remove leading "./".
	filePath = strings.TrimPrefix(filePath, "./")

	ignored := false
	for _, pat := range m.patterns {
		if matchesPattern(pat, filePath) {
			ignored = !pat.negated
		}
	}
	return ignored
}

// matchesPattern checks whether filePath matches a single pattern.
func matchesPattern(pat pattern, filePath string) bool {
	if pat.dirOnly {
		// Directory pattern: "vendor/" matches "vendor/foo/bar.go".
		dir := pat.glob
		if !strings.HasSuffix(dir, "/") {
			dir += "/"
		}
		return strings.HasPrefix(filePath+"/", dir) ||
			strings.Contains(filePath, "/"+dir)
	}

	// If the glob contains no slash, match against the base name only.
	if !strings.Contains(pat.glob, "/") {
		base := path.Base(filePath)
		ok, _ := filepath.Match(pat.glob, base)
		if ok {
			return true
		}
		// Also try matching any path component.
		parts := strings.Split(filePath, "/")
		for _, p := range parts {
			if ok, _ := filepath.Match(pat.glob, p); ok {
				return true
			}
		}
		return false
	}

	// Glob contains a slash: match against the full relative path.
	// Support "**" by replacing it with a temporary token, then using path.Match.
	ok, _ := globMatch(pat.glob, filePath)
	return ok
}

// globMatch supports "**" in patterns by walking path segments.
func globMatch(pat, name string) (bool, error) {
	// Split on "**/" segments and apply filepath.Match to sub-paths.
	if !strings.Contains(pat, "**") {
		ok, err := filepath.Match(pat, name)
		return ok, err
	}

	parts := strings.SplitN(pat, "**/", 2)
	prefix := parts[0]
	suffix := parts[1]

	// "**/" at the start means the suffix can match from any depth.
	if prefix == "" {
		// Match suffix against the full path, or any trailing subpath.
		if ok, _ := filepath.Match(suffix, name); ok {
			return true, nil
		}
		// Try matching against each suffix of the path.
		segs := strings.Split(name, "/")
		for i := range segs {
			sub := strings.Join(segs[i:], "/")
			if ok, _ := filepath.Match(suffix, sub); ok {
				return true, nil
			}
		}
		return false, nil
	}

	// "foo/**/" form: name must start with prefix and suffix matches the rest.
	prefix = strings.TrimSuffix(prefix, "/")
	if !strings.HasPrefix(name, prefix+"/") {
		return false, nil
	}
	rest := strings.TrimPrefix(name, prefix+"/")
	return globMatch(suffix, rest)
}

// parseLine parses one line from a .tassignore file into a pattern.
// Returns (pattern, true) if the line is a valid rule, or (_, false) for
// blank lines and comments.
func parseLine(line string) (pattern, bool) {
	// Strip inline comments (rare but valid in gitignore).
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return pattern{}, false
	}

	pat := pattern{raw: line}

	if strings.HasPrefix(line, "!") {
		pat.negated = true
		line = line[1:]
	}

	if strings.HasSuffix(line, "/") {
		pat.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}

	pat.glob = line
	return pat, true
}
