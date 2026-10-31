// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// wave1SSMFixture mirrors the shared fixture rows in their in-tree
// post-mapper shape. The stub below serves the same rows as SSM JSON
// responses; the in-tree oracle unmarshals the same bytes directly into its
// scanner types.
type wave1SSMFixture struct {
	ScopeID             string                 `json:"scope_id"`
	GenerationID        string                 `json:"generation_id"`
	CollectorInstanceID string                 `json:"collector_instance_id"`
	Parameters          []wave1SSMParameterRow `json:"parameters"`
}

type wave1SSMParameterRow struct {
	ARN                   string
	Name                  string
	Type                  string
	Tier                  string
	DataType              string
	KeyID                 string
	LastModifiedAt        time.Time
	DescriptionPresent    bool
	AllowedPatternPresent bool
	Policies              []wave1SSMPolicyRow
	Tags                  map[string]string
}

type wave1SSMPolicyRow struct {
	Type   string
	Status string
}

func loadWave1SSMFixture(t *testing.T) wave1SSMFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/wave1-ssm-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1SSMFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
