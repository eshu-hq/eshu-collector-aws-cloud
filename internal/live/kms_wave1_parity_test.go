// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"reflect"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// TestWave1KMSParityAgainstInTreeOracle locks the completed KMS live emission
// to the in-tree oracle keys: every fact the in-tree Scanner.Scan derives for
// the shared fixture (testdata/wave1-kms-parity.json) has a satellite twin
// with the identical stable key. The test drives the full production listKMS
// path (stubbed KMS API: ListKeys plus DescribeKey, ListAliases, and
// ListGrants) and converts records to facts exactly as CollectReport does.
// Oracle keys come from the in-tree scan; the re-derivation recipe is in
// testdata/stable-key-provenance.md.
func TestWave1KMSParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1KMSFixture(t)
	cfg := wave1KMSStubConfig(t, fixture)
	records, err := listKMS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}

	const accountID = "123456789012"
	got := map[string]string{}
	for _, item := range records {
		if edge := item.Relationship; edge != nil {
			fact, err := collector.NewRelationshipFact(kmsWave1Relationship(accountID, *edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		for _, edge := range item.Relationships {
			fact, err := collector.NewRelationshipFact(kmsWave1Relationship(accountID, edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		if item.Resource == nil {
			continue
		}
		fact, err := collector.NewResourceFact(kmsWave1Resource(accountID, item.Resource))
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = item.Resource.ResourceID
	}

	want := []string{
		"aws_resource\x00a166e6f4a9b3935347e6a8e864dcac05ee2bdc710f8a7215c77cb914d28e2450",
		"aws_resource\x00b0e9de7232abf9a97fa2992820365e205bd440482b50bc48814263449c7eafa0",
		"aws_relationship\x00cfd612592ec367899b5b60035a6d9d82142c837820af804200d2b3a575d16d88",
		"aws_resource\x00b43a2e3a3a87bf21267cae12f40f591742988a51c0c3805ee9c733fb470bfa22",
		"aws_relationship\x006ddea31409d222c96c5b125bbc6071cc4afec96e8384c0f8c7dc523803563fa9",
		"aws_relationship\x00548d66f23028ba22b7ed6caa8158e0d7df68ec10023506119c6089f029eedca8",
		"aws_resource\x00930e73fa935d52e90891ab4409449de896b2cc186bac6d744f80d17444c6a4a3",
		"aws_resource\x00a167a0ec50354c90f962c5314a63fa6d7ab3d0db9597f1c04270b12b68c46c1d",
		"aws_relationship\x005a8efb8cb3f7164d543086da66f5f63726fdc8a65b39b01108e5c6976bcb13fe",
		"aws_resource\x00db6af0a37d7180208991ead4c4921d6d29802183d8b846793df6f1842a74debb",
		"aws_relationship\x00de7e8b736416c4b15c1422c37119f76b0fbc4269b7fb0e9e8e5a2d2c455deccc",
		"aws_relationship\x003623aa2ec3815d572eec01857afd6a6ece24d54be3574c0c9bd60a5cbc767f33",
		"aws_resource\x002ec91ad52db9620143875fe6cb1ce61ed8e7ac2e8322606ee23e4643ff459768",
		"aws_relationship\x00e955de58a125a996b1abb33bd04af93a49acde08212619960715828396f423ac",
		"aws_resource\x0076709be61e0fa4a4df0f8854e85489173ace52e58d613e06ae9aa89ae024e12f",
		"aws_resource\x002e9031683750715996133645bf4d32ad3635d29f3941de6c322d4bc9a7f204cf",
		"aws_resource\x007058a3b6df52698606e6d2979b805055436aab954911adeb57df8ec896d73969",
		"aws_relationship\x005ed3d2a7d7594c5be0ab3b017b647a44eb185535eeccc92497bffa9be93547c6",
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

// TestWave1KMSPayloadBranches pins the attribute branches stable keys cannot
// see: the ARN-less alias keeps its name-derived identity with no source ARN,
// the target-less stub alias never becomes a record, the grantee-less grant
// keeps its on-key edge but emits no grantee edge, the service-principal
// grantee edge carries no target ARN, absent dates stay empty (not zero
// times), and empty algorithm lists stay nil (not empty slices). Values come
// straight from the fixture rows.
func TestWave1KMSPayloadBranches(t *testing.T) {
	t.Parallel()

	fixture := loadWave1KMSFixture(t)
	cfg := wave1KMSStubConfig(t, fixture)
	records, err := listKMS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 10 {
		t.Fatalf("live records = %d, want 10 (4 keys + 3 aliases + 3 grants)", len(records))
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	keyA, ok := byID["aws_kms_key\x00a1b2c3d4-e5f6-4789-abcd-ef0123456789"]
	if !ok {
		t.Fatal("key A record missing")
	}
	if len(keyA.Relationships) != 0 || keyA.Relationship != nil {
		t.Fatal("key records carry no edges; aliases and grants are separate records")
	}

	aliasB, ok := byID["aws_kms_alias\x00alias/wave1-b-staging"]
	if !ok {
		t.Fatal("ARN-less alias record missing")
	}
	if aliasB.Resource.ARN != "" {
		t.Fatalf("ARN-less alias ARN = %q, want empty", aliasB.Resource.ARN)
	}
	if aliasB.Relationship == nil || aliasB.Relationship.SourceARN != "" {
		t.Fatalf("ARN-less alias edge = %+v, want an edge with empty source ARN", aliasB.Relationship)
	}
	if aliasB.Resource.Attributes["last_updated"] != "" {
		t.Fatalf("ARN-less alias last_updated = %#v, want empty", aliasB.Resource.Attributes["last_updated"])
	}

	for id := range byID {
		if id == "aws_kms_alias\x00alias/wave1-unattached" {
			t.Fatal("target-less stub alias became a record, want it dropped")
		}
	}

	grantB2, ok := byID["aws_kms_grant\x00b1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-b2"]
	if !ok {
		t.Fatal("grantee-less grant record missing")
	}
	if grantB2.Relationship == nil || grantB2.Relationship.RelationshipType != kmsGrantOnKeyRelationship {
		t.Fatalf("grantee-less grant on-key edge = %+v", grantB2.Relationship)
	}
	if len(grantB2.Relationships) != 0 {
		t.Fatalf("grantee-less grant edges = %+v, want none", grantB2.Relationships)
	}
	if operations, ok := grantB2.Resource.Attributes["operations"].([]string); !ok || operations != nil {
		t.Fatalf("grantee-less grant operations = %#v, want nil", grantB2.Resource.Attributes["operations"])
	}

	grantB1, ok := byID["aws_kms_grant\x00b1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-b1"]
	if !ok {
		t.Fatal("service-principal grant record missing")
	}
	if len(grantB1.Relationships) != 1 {
		t.Fatalf("service-principal grant edges = %d, want 1", len(grantB1.Relationships))
	}
	serviceEdge := grantB1.Relationships[0]
	if serviceEdge.TargetARN != "" {
		t.Fatalf("service-principal edge target ARN = %q, want empty", serviceEdge.TargetARN)
	}
	if serviceEdge.TargetResourceID != "Service:s3.amazonaws.com" {
		t.Fatalf("service-principal edge target = %q", serviceEdge.TargetResourceID)
	}

	grantA1, ok := byID["aws_kms_grant\x00a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1"]
	if !ok {
		t.Fatal("grant A1 record missing")
	}
	if len(grantA1.Relationships) != 1 || grantA1.Relationships[0].TargetARN != "arn:aws:iam::123456789012:role/wave1-app" {
		t.Fatalf("grant A1 grantee edge = %+v", grantA1.Relationships)
	}

	keyB, ok := byID["aws_kms_key\x00b1b2c3d4-e5f6-4789-abcd-ef0123456789"]
	if !ok {
		t.Fatal("key B record missing")
	}
	if keyB.Resource.Attributes["creation_date"] != "" {
		t.Fatalf("key B creation_date = %#v, want empty (absent field)", keyB.Resource.Attributes["creation_date"])
	}
	if algorithms, ok := keyB.Resource.Attributes["encryption_algorithms"].([]string); !ok || algorithms != nil {
		t.Fatalf("key B encryption_algorithms = %#v, want nil", keyB.Resource.Attributes["encryption_algorithms"])
	}

	keyC, ok := byID["aws_kms_key\x00c1b2c3d4-e5f6-4789-abcd-ef0123456789"]
	if !ok {
		t.Fatal("key C record missing")
	}
	if keyC.Resource.Attributes["primary_key_arn"] != "arn:aws:kms:us-west-2:123456789012:key/primary-key-id" {
		t.Fatalf("key C primary_key_arn = %#v", keyC.Resource.Attributes["primary_key_arn"])
	}
	if keyC.Resource.Attributes["deletion_date"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("key C deletion_date = %#v", keyC.Resource.Attributes["deletion_date"])
	}
}

// TestWave1KMSAttributeEquality pins the key, alias, and grant attribute
// VALUES the stable-key parity cannot see: keys hash identity only, so a
// swapped alias_name/target_key_id (or a wrong grantee) would pass every key
// gate. Expectations come straight from the fixture rows in
// testdata/wave1-kms-parity.json.
func TestWave1KMSAttributeEquality(t *testing.T) {
	t.Parallel()

	fixture := loadWave1KMSFixture(t)
	cfg := wave1KMSStubConfig(t, fixture)
	records, err := listKMS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	keyA, ok := byID["aws_kms_key\x00a1b2c3d4-e5f6-4789-abcd-ef0123456789"]
	if !ok {
		t.Fatal("key A record missing")
	}
	wantKeyA := map[string]any{
		"key_manager": "CUSTOMER", "key_usage": "ENCRYPT_DECRYPT", "key_spec": "SYMMETRIC_DEFAULT",
		"customer_master_key_spec": "", "key_state": "Enabled", "origin": "AWS_KMS",
		"description":              "wave1 primary key",
		"creation_date":            "2026-01-15T10:30:00Z",
		"deletion_date":            "",
		"enabled":                  true,
		"multi_region":             false,
		"multi_region_key_type":    "",
		"primary_key_arn":          "",
		"encryption_algorithms":    []string{"SYMMETRIC_DEFAULT"},
		"signing_algorithms":       []string(nil),
		"mac_algorithms":           []string(nil),
		"key_agreement_algorithms": []string(nil),
	}
	if !reflect.DeepEqual(keyA.Resource.Attributes, wantKeyA) {
		t.Fatalf("key A attributes = %#v, want %#v", keyA.Resource.Attributes, wantKeyA)
	}

	aliasA, ok := byID["aws_kms_alias\x00arn:aws:kms:us-east-1:123456789012:alias/wave1-a"]
	if !ok {
		t.Fatal("alias A record missing")
	}
	wantAliasA := map[string]any{
		"alias_name":    "alias/wave1-a",
		"target_key_id": "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
		"last_updated":  "2026-02-01T12:00:00Z",
	}
	if !reflect.DeepEqual(aliasA.Resource.Attributes, wantAliasA) {
		t.Fatalf("alias A attributes = %#v, want %#v", aliasA.Resource.Attributes, wantAliasA)
	}
	if aliasA.Relationship == nil {
		t.Fatal("alias A relationship missing")
	}
	wantAliasEdgeA := map[string]any{"alias_name": "alias/wave1-a"}
	if !reflect.DeepEqual(aliasA.Relationship.Attributes, wantAliasEdgeA) {
		t.Fatalf("alias A edge attributes = %#v, want %#v", aliasA.Relationship.Attributes, wantAliasEdgeA)
	}

	grantA1, ok := byID["aws_kms_grant\x00a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1"]
	if !ok {
		t.Fatal("grant A1 record missing")
	}
	wantGrantA1 := map[string]any{
		"grant_id":           "grant-a1",
		"grant_name":         "wave1-grant",
		"key_id":             "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
		"creation_date":      "2026-03-01T09:00:00Z",
		"grantee_principal":  "arn:aws:iam::123456789012:role/wave1-app",
		"retiring_principal": "arn:aws:iam::123456789012:role/wave1-admin",
		"issuing_account":    "123456789012",
		"operations":         []string{"Encrypt", "Decrypt", "GenerateDataKey"},
	}
	if !reflect.DeepEqual(grantA1.Resource.Attributes, wantGrantA1) {
		t.Fatalf("grant A1 attributes = %#v, want %#v", grantA1.Resource.Attributes, wantGrantA1)
	}
	if grantA1.Relationship == nil {
		t.Fatal("grant A1 on-key relationship missing")
	}
	wantGrantEdgeA1 := map[string]any{"grant_id": "grant-a1"}
	if !reflect.DeepEqual(grantA1.Relationship.Attributes, wantGrantEdgeA1) {
		t.Fatalf("grant A1 edge attributes = %#v, want %#v", grantA1.Relationship.Attributes, wantGrantEdgeA1)
	}
	if len(grantA1.Relationships) != 1 {
		t.Fatal("grant A1 grantee relationship missing")
	}
	wantGranteeEdgeA1 := map[string]any{
		"grant_id":           "grant-a1",
		"principal_type":     "AWS",
		"retiring_principal": "arn:aws:iam::123456789012:role/wave1-admin",
	}
	if !reflect.DeepEqual(grantA1.Relationships[0].Attributes, wantGranteeEdgeA1) {
		t.Fatalf("grant A1 grantee edge attributes = %#v, want %#v", grantA1.Relationships[0].Attributes, wantGranteeEdgeA1)
	}

	grantB1, ok := byID["aws_kms_grant\x00b1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-b1"]
	if !ok {
		t.Fatal("service-principal grant record missing")
	}
	wantGrantB1 := map[string]any{
		"grant_id":           "grant-b1",
		"grant_name":         "",
		"key_id":             "b1b2c3d4-e5f6-4789-abcd-ef0123456789",
		"creation_date":      "",
		"grantee_principal":  "s3.amazonaws.com",
		"retiring_principal": "",
		"issuing_account":    "123456789012",
		"operations":         []string{"GenerateDataKey", "Decrypt"},
	}
	if !reflect.DeepEqual(grantB1.Resource.Attributes, wantGrantB1) {
		t.Fatalf("grant B1 attributes = %#v, want %#v", grantB1.Resource.Attributes, wantGrantB1)
	}
	wantGranteeEdgeB1 := map[string]any{
		"grant_id":           "grant-b1",
		"principal_type":     "Service",
		"retiring_principal": "",
	}
	if !reflect.DeepEqual(grantB1.Relationships[0].Attributes, wantGranteeEdgeB1) {
		t.Fatalf("grant B1 grantee edge attributes = %#v, want %#v", grantB1.Relationships[0].Attributes, wantGranteeEdgeB1)
	}
}

// kmsWave1Resource converts a live resource exactly as CollectReport does:
// the loader supplies identity, the claim triple is bound here in tests.
func kmsWave1Resource(accountID string, resource *collector.LiveResource) collector.ResourceObservation {
	return collector.ResourceObservation{
		Boundary:           kmsWave1Boundary(accountID, resource.Region, resource.ServiceKind),
		ARN:                resource.ARN,
		ResourceID:         resource.ResourceID,
		ResourceType:       resource.ResourceType,
		Name:               resource.Name,
		State:              resource.State,
		Tags:               resource.Tags,
		Attributes:         resource.Attributes,
		CorrelationAnchors: append([]string(nil), resource.CorrelationAnchors...),
		SourceRecordID:     resource.SourceRecordID,
		SourceURI:          "aws:kms:us-east-1:wave1-parity",
	}
}

func kmsWave1Relationship(accountID string, edge collector.LiveRelationship) collector.RelationshipObservation {
	observation := relationshipObservation(accountID, edge)
	observation.Boundary.ScopeID = "aws:123456789012:us-east-1"
	observation.Boundary.GenerationID = "aws:123456789012:us-east-1:wave1:1"
	observation.Boundary.CollectorInstanceID = "aws-parity-wave1"
	observation.Boundary.ClaimToken = "wave1-parity-token"
	observation.Boundary.ObservedAt = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	observation.SourceURI = "aws:kms:us-east-1:wave1-parity"
	return observation
}

func kmsWave1Boundary(accountID, region, serviceKind string) collector.Boundary {
	return collector.Boundary{
		AccountID: accountID, Region: region, ServiceKind: serviceKind,
		ScopeID:             "aws:123456789012:us-east-1",
		GenerationID:        "aws:123456789012:us-east-1:wave1:1",
		CollectorInstanceID: "aws-parity-wave1", FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}
