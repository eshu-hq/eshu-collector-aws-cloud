// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"testing"
)

// wave1KMSFixture mirrors the shared fixture rows in their in-tree
// post-mapper shape. The stub below serves the same rows as KMS JSON-protocol
// responses; the in-tree oracle unmarshals the same bytes directly into its
// scanner types (Key, Alias, Grant), so the row fields use those exact Go
// field names. RetiringPrincipalType has no scanner counterpart — the oracle
// ignores it and the stub uses it to pick the retiring API field.
type wave1KMSFixture struct {
	ScopeID             string        `json:"scope_id"`
	GenerationID        string        `json:"generation_id"`
	CollectorInstanceID string        `json:"collector_instance_id"`
	Keys                []wave1KMSRow `json:"keys"`
}

type wave1KMSRow struct {
	ID                     string
	ARN                    string
	Description            string
	KeyManager             string
	KeyUsage               string
	KeySpec                string
	KeyState               string
	Origin                 string
	CreationDate           string
	DeletionDate           string
	Enabled                bool
	MultiRegion            bool
	MultiRegionKeyType     string
	PrimaryKeyARN          string
	EncryptionAlgorithms   []string
	SigningAlgorithms      []string
	MACAlgorithms          []string
	KeyAgreementAlgorithms []string
	Aliases                []wave1KMSAlias
	Grants                 []wave1KMSGrant
}

type wave1KMSAlias struct {
	Name        string
	ARN         string
	TargetKeyID string
	LastUpdated string
}

type wave1KMSGrant struct {
	ID                    string
	Name                  string
	CreationDate          string
	GranteePrincipal      string
	GranteePrincipalType  string
	RetiringPrincipal     string
	RetiringPrincipalType string
	IssuingAccount        string
	Operations            []string
}

func loadWave1KMSFixture(t *testing.T) wave1KMSFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/wave1-kms-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1KMSFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
