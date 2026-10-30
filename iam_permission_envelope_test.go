// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenIAMPermissionKey is the in-tree stable key for the shared-fixture IAM
// statement (go/internal/collector/awscloud/source_parity_8852_test.go,
// parity8852IAMPermissionKey). The satellite seam must reproduce it byte for
// byte from the same fixture section. Re-derivation recipe (oracle commit,
// command, fixture hash): testdata/stable-key-provenance.md.
const frozenIAMPermissionKey = "147e19d094eb81dd4587b18c1e86bb1358ab5d6d7f8367fd75982bf6aac291ab"

type iamParityFixture struct {
	ScopeID             string `json:"scope_id"`
	GenerationID        string `json:"generation_id"`
	CollectorInstanceID string `json:"collector_instance_id"`
	IAMPermission       struct {
		PrincipalARN       string   `json:"principal_arn"`
		PrincipalType      string   `json:"principal_type"`
		PolicySource       string   `json:"policy_source"`
		PolicyName         string   `json:"policy_name"`
		StatementSID       string   `json:"statement_sid"`
		Effect             string   `json:"effect"`
		Actions            []string `json:"actions"`
		Resources          []string `json:"resources"`
		ConditionKeys      []string `json:"condition_keys"`
		ConditionOperators []string `json:"condition_operators"`
		ConditionValues    []string `json:"condition_values_must_not_appear"`
	} `json:"iam_permission"`
}

func iamParityObservation(t *testing.T) (IAMPermissionObservation, []string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/8852-parity-awscloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture iamParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	in := fixture.IAMPermission
	return IAMPermissionObservation{
		Boundary:           boundaryForParity(t, fixture.ScopeID, fixture.GenerationID, fixture.CollectorInstanceID, catalog.ServiceIAM),
		PrincipalARN:       in.PrincipalARN,
		PrincipalType:      in.PrincipalType,
		PolicySource:       in.PolicySource,
		PolicyName:         in.PolicyName,
		StatementSID:       in.StatementSID,
		Effect:             in.Effect,
		Actions:            in.Actions,
		Resources:          in.Resources,
		ConditionKeys:      in.ConditionKeys,
		ConditionOperators: in.ConditionOperators,
		SourceURI:          "aws:iam:role/parity-runtime",
		SourceRecordID:     "iam-row-1",
	}, in.ConditionValues
}

func TestIAMPermissionFactSharedFixtureParity(t *testing.T) {
	t.Parallel()

	observation, forbidden := iamParityObservation(t)
	fact, err := NewIAMPermissionFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindIAMPermission || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenIAMPermissionKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenIAMPermissionKey)
	}
	// Actions normalize case-insensitively with surrounding whitespace
	// trimmed: the fixture's iam:passrole/iam:PassRole pair collapses to one.
	actions, ok := fact.Payload["actions"].([]string)
	if !ok {
		t.Fatalf("actions = %#v, want string list", fact.Payload["actions"])
	}
	joined := strings.Join(actions, ",")
	if joined != "iam:passrole,sts:assumerole" {
		t.Fatalf("actions = %q, want normalized set", joined)
	}
	// Condition values must never reach the payload: keys only.
	raw, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range forbidden {
		if strings.Contains(string(raw), value) {
			t.Fatalf("payload contains condition value %q, want keys only", value)
		}
	}
	decoded, err := factschema.DecodeAWSIAMPermission(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.Effect != "Allow" {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestIAMPermissionFactRejectsHostileInput(t *testing.T) {
	t.Parallel()

	observation, _ := iamParityObservation(t)
	observation.PrincipalARN = "   "
	if _, err := NewIAMPermissionFact(observation); err == nil {
		t.Fatal("blank principal_arn accepted")
	}
	observation, _ = iamParityObservation(t)
	observation.Effect = "Maybe"
	if _, err := NewIAMPermissionFact(observation); err == nil {
		t.Fatal("non-Allow/Deny effect accepted")
	}
	observation, _ = iamParityObservation(t)
	observation.PolicySource = ""
	if _, err := NewIAMPermissionFact(observation); err == nil {
		t.Fatal("blank policy_source accepted")
	}
}
