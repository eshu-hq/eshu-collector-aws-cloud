// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ciWorkflowFile is the part of the CI workflow the lane-selection tests
// read: the jobs map with each job's if condition, permissions, and steps.
type ciWorkflowFile struct {
	Jobs map[string]ciWorkflowJob `yaml:"jobs"`
}

// ciWorkflowJob carries the lane-selection surface of one CI job.
type ciWorkflowJob struct {
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []ciWorkflowStep  `yaml:"steps"`
}

// ciWorkflowStep carries the selection and body surface of one job step.
type ciWorkflowStep struct {
	Name string         `yaml:"name"`
	If   string         `yaml:"if"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

func readCIWorkflow(t *testing.T) ciWorkflowFile {
	t.Helper()

	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow ciWorkflowFile
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	if len(workflow.Jobs) == 0 {
		t.Fatal("ci.yml defines no jobs")
	}
	return workflow
}

// TestImageLaneRunsOnGoSources keeps the shipped artifact validated on
// PRs that change what it embeds: the Dockerfile COPYs go.mod/go.sum,
// COPYs the whole context (which keeps .go sources), and go-builds the
// binary, so a Go-source or go.mod PR must select the image lane. A
// go.mod toolchain bump past the pinned base would otherwise pass every
// Go lane yet break docker build, surfacing only as post-merge red main.
func TestImageLaneRunsOnGoSources(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	job, ok := workflow.Jobs["image"]
	if !ok {
		t.Fatal("ci.yml has no image job")
	}
	if !strings.Contains(job.If, "needs.changes.outputs.go == 'true'") {
		t.Errorf("job image if = %q, want the go selecting clause: Go sources ship in the image", job.If)
	}
	if strings.Contains(job.If, "needs.changes.outputs.go !=") {
		t.Errorf("job image if = %q, want == 'true', not an inverted comparison", job.If)
	}
	if strings.Contains(job.If, "needs.changes.outputs.go == 'false'") {
		t.Errorf("job image if = %q, want == 'true', not == 'false'", job.If)
	}
}

// readCIFilters returns the dorny/paths-filter group map from the changes
// job: group name to its include/exclude patterns.
func readCIFilters(t *testing.T, workflow ciWorkflowFile) map[string][]string {
	t.Helper()

	changes, ok := workflow.Jobs["changes"]
	if !ok {
		t.Fatal("ci.yml has no changes job")
	}
	for _, step := range changes.Steps {
		raw, ok := step.With["filters"]
		if !ok {
			continue
		}
		text, ok := raw.(string)
		if !ok {
			t.Fatalf("changes filter block is %T, want a YAML string", raw)
		}
		var filters map[string][]string
		if err := yaml.Unmarshal([]byte(text), &filters); err != nil {
			t.Fatal(err)
		}
		return filters
	}
	t.Fatal("changes job has no paths-filter step with a filters block")
	return nil
}

// TestUnclassifiedPathsRunFullLanes is the fail-closed rule from issue #6:
// a PR that touches only paths no filter classifies (for example
// .gitignore) must still run lint, test, and race through the misc
// catch-all instead of skipping every lane.
func TestUnclassifiedPathsRunFullLanes(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	for _, lane := range []string{"lint", "test", "race"} {
		job, ok := workflow.Jobs[lane]
		if !ok {
			t.Fatalf("ci.yml has no %s job", lane)
		}
		if !strings.Contains(job.If, "needs.changes.outputs.misc == 'true'") {
			t.Errorf("job %s if = %q, want the misc catch-all clause", lane, job.If)
		}
	}

	filters := readCIFilters(t, workflow)
	misc, ok := filters["misc"]
	if !ok {
		t.Fatal("changes filters have no misc catch-all group")
	}
	patterns := map[string]bool{}
	for _, p := range misc {
		patterns[p] = true
	}
	// The catch-all matches everything, keeps docs-only PRs skipping,
	// and negates every classified pattern so narrow lanes keep shape.
	for _, want := range []string{"**", "!**/*.md", "!LICENSE", "!config.example.yaml"} {
		if !patterns[want] {
			t.Errorf("misc filter = %q, want pattern %q", misc, want)
		}
	}
	for group, entries := range filters {
		if group == "misc" {
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry, "!") {
				continue
			}
			if !patterns["!"+entry] {
				t.Errorf("misc filter = %q, want negation %q of classified %s pattern %q",
					misc, "!"+entry, group, entry)
			}
		}
	}
}

// TestNarrowLanesKeepSkipBehavior guards the other half of issue #6:
// shell-only PRs still run shell only, and fixture-JSON-only PRs still
// run test (and race) without lint. The misc catch-all must not leak
// into the narrow lanes. Race deliberately keeps the fixtures trigger:
// fixture changes can move statement coverage, so fixture-only PRs keep
// the -race and COVERAGE_FLOOR signal (see TestFixtureChangesKeepRaceSignal).
func TestNarrowLanesKeepSkipBehavior(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	for _, lane := range []string{"lint", "test", "race"} {
		if strings.Contains(workflow.Jobs[lane].If, "needs.changes.outputs.shell") {
			t.Errorf("job %s if = %q, want no shell clause: shell-only PRs must not run Go lanes",
				lane, workflow.Jobs[lane].If)
		}
	}
	for _, lane := range []string{"shell", "image", "govulncheck"} {
		job, ok := workflow.Jobs[lane]
		if !ok {
			t.Fatalf("ci.yml has no %s job", lane)
		}
		if strings.Contains(job.If, "needs.changes.outputs.misc") {
			t.Errorf("job %s if = %q, want no misc clause: narrow lanes keep their shape",
				lane, job.If)
		}
	}
	shell := workflow.Jobs["shell"]
	if !strings.Contains(shell.If, "needs.changes.outputs.shell == 'true'") {
		t.Errorf("job shell if = %q, want the shell selecting clause", shell.If)
	}
}

// TestFixtureChangesKeepRaceSignal pins the lane mapping the coverage floor
// depends on: fixture-only changes select test and race (never lint), so a
// fixture PR that moves statement coverage still runs the -race suite and
// the COVERAGE_FLOOR check. Removing the fixtures clause from the race
// condition fails this test.
func TestFixtureChangesKeepRaceSignal(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	for _, lane := range []string{"test", "race"} {
		job, ok := workflow.Jobs[lane]
		if !ok {
			t.Fatalf("ci.yml has no %s job", lane)
		}
		if !strings.Contains(job.If, "needs.changes.outputs.fixtures == 'true'") {
			t.Errorf("job %s if = %q, want the fixtures selecting clause: fixture changes can move coverage", lane, job.If)
		}
	}
	lint, ok := workflow.Jobs["lint"]
	if !ok {
		t.Fatal("ci.yml has no lint job")
	}
	if strings.Contains(lint.If, "needs.changes.outputs.fixtures") {
		t.Errorf("job lint if = %q, want no fixtures clause: fixture-only PRs skip lint", lint.If)
	}
}

// TestFixturesFilterIsGrepProven enforces the epic classification rule on
// the fixtures group: a file is test-class only if a test opens it or a
// an embedded file reaches it. config.example.yaml has no test readers
// (README-only) and .github/dependabot.yml has none either, so neither
// may hide in fixtures while real unclassified paths skip every lane.
func TestFixturesFilterIsGrepProven(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	filters := readCIFilters(t, workflow)
	fixtures := filters["fixtures"]
	patterns := map[string]bool{}
	for _, p := range fixtures {
		patterns[p] = true
	}
	for _, proven := range []string{"testdata/**", "**/*.json", "manifest.yaml", "grant.example.json"} {
		if !patterns[proven] {
			t.Errorf("fixtures filter = %q, want grep-proven entry %q", fixtures, proven)
		}
	}
	for _, unproven := range []string{"**/*.yaml", "**/*.yml", "*.example.*"} {
		if patterns[unproven] {
			t.Errorf("fixtures filter = %q, want no unproven glob %q: config.example.yaml and .github/dependabot.yml have no test readers",
				fixtures, unproven)
		}
	}
}

// TestGosecScheduledFindingsFileIssue requires the scheduled gosec job to
// carry the same file-or-update issue step the govulncheck job has: a
// finding count that fails scheduled runs with findings, and an
// issue step gated on that failure that opens or updates an issue.
func TestGosecScheduledFindingsFileIssue(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	gosec, ok := workflow.Jobs["gosec"]
	if !ok {
		t.Fatal("ci.yml has no gosec job")
	}
	if gosec.Permissions["issues"] != "write" {
		t.Errorf("gosec permissions = %v, want issues: write for scheduled findings issues",
			gosec.Permissions)
	}
	var sawCountGate, sawIssueStep bool
	for _, step := range gosec.Steps {
		if strings.Contains(step.Run, "gosec.sarif") &&
			strings.Contains(step.Run, "github.event_name") &&
			strings.Contains(step.Run, "schedule") &&
			strings.Contains(step.Run, "exit 1") {
			sawCountGate = true
		}
		if strings.Contains(step.Run, "gh issue create") &&
			strings.Contains(step.If, "failure()") &&
			strings.Contains(step.If, "github.event_name == 'schedule'") {
			sawIssueStep = true
		}
	}
	if !sawCountGate {
		t.Error("gosec has no finding-count step that fails scheduled runs with findings")
	}
	if !sawIssueStep {
		t.Error("gosec has no file-or-update issue step gated on failure() && schedule")
	}
}
