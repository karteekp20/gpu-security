package test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Build-pipeline supply chain (CLAUDE.md P8, docs/threat-model.md T6).
//
// The release job holds a token that can create a release and mint an OIDC
// identity which signs binaries in our name. Everything that executes in it
// is therefore part of the trust boundary of every artifact a buyer
// downloads, and `uses: owner/action@v4` is a mutable reference: whoever
// controls that repository can repoint the tag at new code.
//
// Every `uses:` in this repository is pinned to a commit SHA, and
// `.github/workflows/ci.yml` says so in a comment ending "this is the claim
// being true". It was not a claim anything checked. Writing a pin is a
// convention; the next edit, or a merge that resolves a conflict the easy
// way, restores a tag and nothing fails.
//
// The third test is the one this repository paid for. A SHA pin on
// `sigstore/cosign-installer` pins the *installer*, not the cosign binary it
// downloads - and an unpinned cosign 3 silently broke the v0.1.1 release
// (decision row 2026-10-30). Pinning one level and believing you pinned two
// is the same error as a mutable tag, one layer down.

var (
	usesLine = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*(\S+)(.*)$`)
	// usesLoose matches a `uses:` key whether or not a value follows on the
	// same line. Comparing the two counts is how a partial parse failure is
	// caught: a step the strict pattern misses is a step nothing checks.
	usesLoose  = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:`)
	shaPinned  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionTag = regexp.MustCompile(`#\s*v?\d`)
)

// workflowsWithoutActions lists workflows that legitimately run no
// third-party action, with the reason. It exists so that the common case
// stays a hard failure: a workflow that stops yielding `uses:` lines is far
// more likely to be a parser that broke than a job that genuinely uses
// nothing, and the difference must be someone's decision rather than a
// silent pass. Empty today.
var workflowsWithoutActions = map[string]string{}

type actionRef struct {
	file, raw, trailing string
	line                int
}

func workflowActions(t *testing.T) []actionRef {
	t.Helper()
	dir := filepath.Join("..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []actionRef
	var files int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		files++
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		body := string(b)
		var inFile int
		for _, m := range usesLine.FindAllStringSubmatchIndex(body, -1) {
			raw := body[m[2]:m[3]]
			trailing := body[m[4]:m[5]]
			inFile++
			out = append(out, actionRef{
				file: name, raw: raw, trailing: trailing,
				line: strings.Count(body[:m[2]], "\n") + 1,
			})
		}
		// Per file, not just overall. A whole workflow dropping out of the
		// parse is invisible in a total, because the other files keep it
		// non-zero - which is exactly what a first version of this test
		// missed: renaming `uses:` to `usez:` throughout ci.yml left the
		// suite green.
		if inFile == 0 {
			if why, ok := workflowsWithoutActions[name]; ok {
				t.Logf("%s runs no third-party action (%s)", name, why)
			} else {
				t.Errorf("%s contains no recognisable `uses:` step. If it genuinely "+
					"runs no third-party action, add it to workflowsWithoutActions "+
					"with the reason - one line, and the exception is on the record. "+
					"Otherwise this parser no longer understands the file and has "+
					"silently stopped checking it", name)
			}
		}
		if loose := len(usesLoose.FindAllString(body, -1)); loose != inFile {
			t.Errorf("%s has %d `uses:` keys but %d parsed with a value: %d step(s) "+
				"are not being checked at all", name, loose, inFile, loose-inFile)
		}
	}
	// Guard the guard. Every test below iterates what this found, so a
	// renamed directory or a format change would leave them passing while
	// inspecting nothing.
	if files == 0 {
		t.Fatal("no workflow files found; this suite silently stopped guarding the build")
	}
	if len(out) == 0 {
		t.Fatal("parsed no `uses:` lines out of the workflows; the parser broke, " +
			"not the pipeline")
	}
	return out
}

// TestEveryThirdPartyActionIsPinnedToASHA is T6, as a gate rather than a
// comment.
func TestEveryThirdPartyActionIsPinnedToASHA(t *testing.T) {
	for _, a := range workflowActions(t) {
		// A local composite action is this repository's own code and is
		// covered by review, not by pinning.
		if strings.HasPrefix(a.raw, "./") {
			continue
		}
		owner, ref, found := strings.Cut(a.raw, "@")
		if !found {
			t.Errorf("%s:%d: `uses: %s` has no version at all, so it floats on the "+
				"action's default branch", a.file, a.line, a.raw)
			continue
		}
		if !shaPinned.MatchString(ref) {
			t.Errorf("%s:%d: %s is pinned to %q, which is mutable - whoever controls "+
				"that repository can repoint it at new code that runs inside the job "+
				"that signs our binaries. Pin the 40-character commit SHA and put the "+
				"version in a trailing comment", a.file, a.line, owner, ref)
		}
	}
}

// TestEveryPinnedActionNamesItsVersion keeps the pins legible. A bare SHA is
// unreviewable - nobody can tell v7.0.1 from a year-old commit by reading it
// - and the trailing comment is what Dependabot rewrites on an update, so
// dropping it quietly takes the action out of automated updates too.
func TestEveryPinnedActionNamesItsVersion(t *testing.T) {
	for _, a := range workflowActions(t) {
		if strings.HasPrefix(a.raw, "./") || !strings.Contains(a.raw, "@") {
			continue
		}
		if !versionTag.MatchString(a.trailing) {
			t.Errorf("%s:%d: %s is SHA-pinned with no `# vX.Y.Z` comment: the pin is "+
				"unreviewable by eye and Dependabot has nothing to rewrite",
				a.file, a.line, a.raw)
		}
	}
}

// TestCosignInstallerPinsTheBinaryItInstalls is the lesson of 2026-10-30. The
// installer was SHA-pinned and the release still broke, because the installer
// downloads whatever cosign version it likes by default and cosign 3 removed
// the flags the workflow used. A pinned installer is not a pinned tool.
func TestCosignInstallerPinsTheBinaryItInstalls(t *testing.T) {
	dir := filepath.Join("..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	seen := false
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		body := string(b)
		if !strings.Contains(body, "cosign-installer@") {
			continue
		}
		seen = true
		if !regexp.MustCompile(`cosign-release:\s*"?v\d+\.\d+\.\d+`).MatchString(body) {
			t.Errorf("%s uses cosign-installer without pinning `cosign-release` to an "+
				"exact version. The SHA pin covers the installer, not the cosign binary "+
				"it downloads - which is precisely how the v0.1.1 release broke, and "+
				"this binary is what signs every artifact a buyer verifies",
				e.Name())
		}
	}
	if !seen {
		t.Skip("no workflow installs cosign; nothing to pin")
	}
}
