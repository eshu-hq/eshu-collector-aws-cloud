// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// wave1ECRFixture mirrors the shared fixture rows in their in-tree
// post-mapper shape. The stub below serves the same rows as ECR JSON-protocol
// responses; the in-tree oracle unmarshals the same bytes directly into its
// scanner types.
type wave1ECRFixture struct {
	ScopeID             string           `json:"scope_id"`
	GenerationID        string           `json:"generation_id"`
	CollectorInstanceID string           `json:"collector_instance_id"`
	Repositories        []wave1ECRRow    `json:"repositories"`
	Images              []wave1ECRImage  `json:"images"`
	Policies            []wave1ECRPolicy `json:"policies"`
}

type wave1ECRRow struct {
	ARN                string
	Name               string
	URI                string
	RegistryID         string
	ImageTagMutability string
	EncryptionType     string
	KMSKey             string
	ScanOnPush         bool
	CreatedAt          time.Time
	Tags               map[string]string
}

type wave1ECRImage struct {
	RepositoryARN     string
	RepositoryName    string
	RegistryID        string
	ImageDigest       string
	ManifestDigest    string
	Tags              []string
	PushedAt          time.Time
	ImageSizeInBytes  int64
	ManifestMediaType string
	ArtifactMediaType string
}

type wave1ECRPolicy struct {
	RepositoryARN   string
	RepositoryName  string
	RegistryID      string
	PolicyText      string
	LastEvaluatedAt time.Time
}

func loadWave1ECRFixture(t *testing.T) wave1ECRFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/wave1-ecr-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1ECRFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
