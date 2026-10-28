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
// read: the jobs map with each job's if condition.
type ciWorkflowFile struct {
	Jobs map[string]struct {
		If string `yaml:"if"`
	} `yaml:"jobs"`
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

// TestFixtureOnlyPRSkipsRace keeps fixture-only PRs cheap: the epic runs
// the race lane on Go source or module changes only, never for fixtures the
// tests read. A fixtures clause in the race condition would bill every
// fixture PR for a 30-minute race job without new code to race.
func TestFixtureOnlyPRSkipsRace(t *testing.T) {
	t.Parallel()

	workflow := readCIWorkflow(t)
	race, ok := workflow.Jobs["race"]
	if !ok {
		t.Fatal("ci.yml has no race job")
	}
	if !strings.Contains(race.If, "needs.changes.outputs.go == 'true'") {
		t.Errorf("job race if = %q, want the go selecting clause", race.If)
	}
	if strings.Contains(race.If, "needs.changes.outputs.fixtures") {
		t.Errorf("job race if = %q, want no fixtures clause: fixture PRs run test only", race.If)
	}
	test, ok := workflow.Jobs["test"]
	if !ok {
		t.Fatal("ci.yml has no test job")
	}
	if !strings.Contains(test.If, "needs.changes.outputs.fixtures == 'true'") {
		t.Errorf("job test if = %q, want the fixtures selecting clause", test.If)
	}
	shell, ok := workflow.Jobs["shell"]
	if !ok {
		t.Fatal("ci.yml has no shell job")
	}
	if strings.Contains(shell.If, "needs.changes.outputs.go") || strings.Contains(shell.If, "needs.changes.outputs.fixtures") {
		t.Errorf("job shell if = %q, want shell selection only", shell.If)
	}
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
