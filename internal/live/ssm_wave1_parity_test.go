// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// TestWave1SSMParityAgainstInTreeOracle locks the completed SSM live emission
// to the in-tree oracle keys: every fact the in-tree Scanner.Scan derives for
// the shared fixture (testdata/wave1-ssm-parity.json) has a satellite twin
// with the identical stable key. The test drives the full production listSSM
// path (stubbed SSM API: DescribeParameters plus per-parameter
// ListTagsForResource) and converts records to facts exactly as CollectReport
// does. Oracle keys come from the in-tree scan; the re-derivation recipe is
// in testdata/stable-key-provenance.md.
func TestWave1SSMParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg := wave1SSMStubConfig(t, fixture)
	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	const accountID = "123456789012"
	got := map[string]string{}
	for _, item := range records {
		if edge := item.Relationship; edge != nil {
			fact, err := collector.NewRelationshipFact(ssmWave1Relationship(accountID, *edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		for _, edge := range item.Relationships {
			fact, err := collector.NewRelationshipFact(ssmWave1Relationship(accountID, edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		if item.Resource == nil {
			continue
		}
		fact, err := collector.NewResourceFact(ssmWave1Resource(accountID, item.Resource))
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = item.Resource.ResourceID
	}

	want := []string{
		"aws_resource\x007b6bc0617577ac44aa8437d219a0442b0a5656c2eb803ca62f9d4285ef956ff8",
		"aws_relationship\x002d7c3fb735afdb424480f4fbbc46798aad4e54d4bfbd2ffbcd1709b8cd74104c",
		"aws_resource\x0039c75ea69f11f5c0c28810c70545f135694bda9acf7540f645384f9d4141045e",
		"aws_relationship\x001c12ea50ba44595739df270bffad7558c50a7dc946ee3b3dcd37cdead761ad5f",
		"aws_resource\x00dde48d93d2bf1954662390619cb2ff18552245db1323a0fe1bff1a52a1fff08b",
	}
	if len(got) != len(want) {
		for key, id := range got {
			t.Logf("extra fact %q from %q", key, id)
		}
		t.Fatalf("parity fact count = %d, want %d", len(got), len(want))
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("missing oracle fact %q", key)
		}
	}
}

// TestWave1SSMPayloadBranches pins the attribute branches stable keys cannot
// see: the KMS-less parameter carries no edge, the alias-keyed edge keeps an
// empty target ARN, the ARN-less parameter falls back to its name, absent
// timestamps stay nil (not zero times), untagged rows stay nil (not empty
// maps), and raw descriptions, patterns, and policy JSON never enter a fact.
// Values come straight from the fixture rows.
func TestWave1SSMPayloadBranches(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg := wave1SSMStubConfig(t, fixture)
	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	parameterA, ok := byID["aws_ssm_parameter\x00arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password"]
	if !ok {
		t.Fatal("parameter A record missing")
	}
	if parameterA.Relationship == nil || parameterA.Relationship.TargetARN != "arn:aws:kms:us-east-1:123456789012:key/wave1-key-1" {
		t.Fatalf("parameter A relationship = %+v, want KMS ARN edge", parameterA.Relationship)
	}

	parameterB, ok := byID["aws_ssm_parameter\x00arn:aws:ssm:us-east-1:123456789012:parameter/wave1/app/config"]
	if !ok {
		t.Fatal("parameter B record missing")
	}
	if parameterB.Relationship == nil {
		t.Fatal("parameter B relationship missing (alias key still links)")
	}
	if parameterB.Relationship.TargetResourceID != "alias/wave1" || parameterB.Relationship.TargetARN != "" {
		t.Fatalf("parameter B relationship = %+v, want alias target with empty ARN", parameterB.Relationship)
	}
	if parameterB.Resource.Attributes["last_modified_at"] != nil {
		t.Fatalf("parameter B last_modified_at = %#v, want nil (absent field)", parameterB.Resource.Attributes["last_modified_at"])
	}
	if parameterB.Resource.Tags != nil {
		t.Fatalf("parameter B tags = %#v, want nil", parameterB.Resource.Tags)
	}
	if policies, ok := parameterB.Resource.Attributes["policies"].([]map[string]string); !ok || policies != nil {
		t.Fatalf("parameter B policies = %#v, want typed nil", parameterB.Resource.Attributes["policies"])
	}

	parameterC, ok := byID["aws_ssm_parameter\x00/wave1/ami/latest"]
	if !ok {
		t.Fatal("ARN-less parameter record missing")
	}
	if parameterC.Resource.ARN != "" {
		t.Fatalf("ARN-less parameter ARN = %q, want empty", parameterC.Resource.ARN)
	}
	if parameterC.Resource.SourceRecordID != "/wave1/ami/latest" {
		t.Fatalf("ARN-less parameter SourceRecordID = %q, want name fallback", parameterC.Resource.SourceRecordID)
	}
	if parameterC.Relationship != nil {
		t.Fatalf("ARN-less parameter relationship = %+v, want nil (no key)", parameterC.Relationship)
	}

	for _, record := range records {
		if record.Resource == nil {
			continue
		}
		encoded, err := json.Marshal(record.Resource.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		for _, leaked := range []string{wave1SSMStubDescriptionText, wave1SSMStubPatternText, wave1SSMStubPolicyText} {
			if strings.Contains(string(encoded), leaked) {
				t.Fatalf("record %q leaks raw text %q: %s", record.Resource.ResourceID, leaked, encoded)
			}
		}
	}
}

// TestWave1SSMParameterAttributeEquality pins the parameter attribute VALUES
// the stable-key parity cannot see: keys hash identity only, so swapped
// type/tier values (or a wrong key_id, presence flag, policy entry, or tag)
// would pass every key gate. Expectations come straight from the fixture
// rows in testdata/wave1-ssm-parity.json.
func TestWave1SSMParameterAttributeEquality(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg := wave1SSMStubConfig(t, fixture)
	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	parameterA, ok := byID["aws_ssm_parameter\x00arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password"]
	if !ok {
		t.Fatal("parameter A record missing")
	}
	wantA := map[string]any{
		"type":                    "SecureString",
		"tier":                    "Advanced",
		"data_type":               "text",
		"key_id":                  "arn:aws:kms:us-east-1:123456789012:key/wave1-key-1",
		"last_modified_at":        time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		"description_present":     true,
		"allowed_pattern_present": true,
		"policies": []map[string]string{
			{"type": "Expiration", "status": "Pending"},
			{"type": "NoChangeNotification", "status": "Finished"},
		},
	}
	if !reflect.DeepEqual(parameterA.Resource.Attributes, wantA) {
		t.Fatalf("parameter A attributes = %#v, want %#v", parameterA.Resource.Attributes, wantA)
	}
	if wantTags := map[string]string{"env": "wave1", "team": "platform"}; !reflect.DeepEqual(parameterA.Resource.Tags, wantTags) {
		t.Fatalf("parameter A tags = %#v, want %#v (padded key trimmed)", parameterA.Resource.Tags, wantTags)
	}
	if parameterA.Relationship == nil {
		t.Fatal("parameter A relationship missing")
	}
	if got := parameterA.Relationship.SourceRecordID; got != "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password->ssm_parameter_uses_kms_key:arn:aws:kms:us-east-1:123456789012:key/wave1-key-1" {
		t.Fatalf("parameter A edge SourceRecordID = %q", got)
	}

	parameterB, ok := byID["aws_ssm_parameter\x00arn:aws:ssm:us-east-1:123456789012:parameter/wave1/app/config"]
	if !ok {
		t.Fatal("parameter B record missing")
	}
	wantB := map[string]any{
		"type":                    "String",
		"tier":                    "Standard",
		"data_type":               "text",
		"key_id":                  "alias/wave1",
		"last_modified_at":        nil,
		"description_present":     false,
		"allowed_pattern_present": false,
		"policies":                []map[string]string(nil),
	}
	if !reflect.DeepEqual(parameterB.Resource.Attributes, wantB) {
		t.Fatalf("parameter B attributes = %#v, want %#v", parameterB.Resource.Attributes, wantB)
	}

	parameterC, ok := byID["aws_ssm_parameter\x00/wave1/ami/latest"]
	if !ok {
		t.Fatal("parameter C record missing")
	}
	wantC := map[string]any{
		"type":                    "StringList",
		"tier":                    "Intelligent-Tiering",
		"data_type":               "aws:ec2:image",
		"key_id":                  "",
		"last_modified_at":        time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		"description_present":     true,
		"allowed_pattern_present": false,
		"policies": []map[string]string{
			{"type": "ExpirationNotification", "status": "InProgress"},
		},
	}
	if !reflect.DeepEqual(parameterC.Resource.Attributes, wantC) {
		t.Fatalf("parameter C attributes = %#v, want %#v", parameterC.Resource.Attributes, wantC)
	}
}

// TestWave1SSMParameterRecordRejectsEmptyIdentity locks the one deliberate
// satellite deviation: a row with neither ARN nor name fails instead of
// emitting an empty-ID resource the in-tree mapper would trust.
func TestWave1SSMParameterRecordRejectsEmptyIdentity(t *testing.T) {
	t.Parallel()

	if _, err := ssmParameterRecord(ssmtypes.ParameterMetadata{}, nil, "us-east-1"); err == nil {
		t.Fatal("ssmParameterRecord(empty) error = nil, want identity failure")
	}
}

// ssmWave1Resource converts a live resource exactly as CollectReport does:
// the loader supplies identity, the claim triple is bound here in tests.
func ssmWave1Resource(accountID string, resource *collector.LiveResource) collector.ResourceObservation {
	return collector.ResourceObservation{
		Boundary:           ssmWave1Boundary(accountID, resource.Region, resource.ServiceKind),
		ARN:                resource.ARN,
		ResourceID:         resource.ResourceID,
		ResourceType:       resource.ResourceType,
		Name:               resource.Name,
		State:              resource.State,
		Tags:               resource.Tags,
		Attributes:         resource.Attributes,
		CorrelationAnchors: append([]string(nil), resource.CorrelationAnchors...),
		SourceRecordID:     resource.SourceRecordID,
		SourceURI:          "aws:ssm:us-east-1:wave1-parity",
	}
}

func ssmWave1Relationship(accountID string, edge collector.LiveRelationship) collector.RelationshipObservation {
	observation := relationshipObservation(accountID, edge)
	observation.Boundary.ScopeID = "aws:123456789012:us-east-1"
	observation.Boundary.GenerationID = "aws:123456789012:us-east-1:wave1:1"
	observation.Boundary.CollectorInstanceID = "aws-parity-wave1"
	observation.Boundary.ClaimToken = "wave1-parity-token"
	observation.Boundary.ObservedAt = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	observation.SourceURI = "aws:ssm:us-east-1:wave1-parity"
	return observation
}

func ssmWave1Boundary(accountID, region, serviceKind string) collector.Boundary {
	return collector.Boundary{
		AccountID: accountID, Region: region, ServiceKind: serviceKind,
		ScopeID:             "aws:123456789012:us-east-1",
		GenerationID:        "aws:123456789012:us-east-1:wave1:1",
		CollectorInstanceID: "aws-parity-wave1", FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}
