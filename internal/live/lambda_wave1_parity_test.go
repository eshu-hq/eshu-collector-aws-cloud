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

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// TestWave1LambdaParityAgainstInTreeOracle locks the completed Lambda live
// emission to the in-tree oracle keys: every fact the in-tree Scanner.Scan
// derives for the shared fixture (testdata/wave1-lambda-parity.json) has a
// satellite twin with the identical stable key. The test drives the full
// production listLambda path (stubbed Lambda API: ListFunctions plus per
// function GetFunction, ListAliases, ListEventSourceMappings) and converts
// records to facts exactly as CollectReport does. Oracle keys come from the
// in-tree scan; the re-derivation recipe is in
// testdata/stable-key-provenance.md.
func TestWave1LambdaParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1LambdaFixture(t)
	cfg := wave1LambdaStubConfig(t, fixture)
	records, err := listLambda(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	const accountID = "123456789012"
	got := map[string]string{}
	for _, item := range records {
		if edge := item.Relationship; edge != nil {
			fact, err := collector.NewRelationshipFact(lambdaWave1Relationship(accountID, *edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		for _, edge := range item.Relationships {
			fact, err := collector.NewRelationshipFact(lambdaWave1Relationship(accountID, edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		if item.Resource == nil {
			continue
		}
		fact, err := collector.NewResourceFact(lambdaWave1Resource(accountID, item.Resource))
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = item.Resource.ResourceID
	}

	want := []string{
		"aws_resource\x00fa37b448f395924e3ad6cadea02d260e25e87ff994976f347c70078e8228c09d",
		"aws_relationship\x00efae44c5f16e7f9bf63b140649c0b9951571936d39a9bd50b806fe07ffbb69ca",
		"aws_relationship\x00bcc505261e1bf47d2ffb3aea19998602a7158e096433d2eda952389260cdc7b3",
		"aws_relationship\x00d1edae98764b560dfa14f839a3332a42b40517b894ce10a835c4eed0ac891cdc",
		"aws_relationship\x00e9fb98e797de8d26f90f4a6410f2d616f40f444887245615cee592a8d5087cb1",
		"aws_resource\x000a18e0f288b56e0c5f7366a4c7b1c912bb30e91744be6ca5d9f00e52d66df196",
		"aws_relationship\x006597492b4f3894f4d99718185fb36a7c61bce82a89c37c6c576f676bf6e7e2cb",
		"aws_resource\x008f1d9720e169c8dfd306127e196a0a346d4fc90d65f6985eeaeac7946d376715",
		"aws_resource\x000272b442722ce4612397661e7af6a6fac85074112d7f3d07d557b240c1218f59",
		"aws_relationship\x00798b427fcdc4d315a4e253725601ddb16bcfdce6584eee770319e6c73396624b",
		"aws_resource\x004d58f839ca1dccea056d6a5bdc99a365f7eae255bfc62b1752d5cba9a667bc62",
		"aws_relationship\x008a42c89bc451d966d1b286509a4d26d8793a8851ee561082d025f308d0fc3b83",
		"aws_resource\x0028b276d07d237cd4674c6316610d04b5a9b48d649e96bd0e3c4f067b77ad914e",
		"aws_relationship\x002b5f15a4627a9fa0e84374e4899a261ee75f09861ff973cad16f12cf71384d1b",
		"aws_resource\x00685dd2545089855187630efc47808cc679029c4363613ecb56d83facf60ec015",
		"aws_relationship\x00bb934c2e933f18a7df4d2d8461024ab07d511583fd7e978cccd51d8a6972f221",
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

// TestWave1LambdaPayloadBranches pins the attribute branches stable keys
// cannot see: the VPC-less image function carries no placement edges and no
// role link, absent timestamps stay nil (not zero times), untagged rows stay
// nil (not empty maps), raw environment values never enter a fact, and the
// ARN-less alias and UUID-only mapping keep their parent-derived identities.
// Values come straight from the fixture rows.
func TestWave1LambdaPayloadBranches(t *testing.T) {
	t.Parallel()

	fixture := loadWave1LambdaFixture(t)
	cfg := wave1LambdaStubConfig(t, fixture)
	records, err := listLambda(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	functionA, ok := byID["aws_lambda_function\x00arn:aws:lambda:us-east-1:123456789012:function:wave1-a"]
	if !ok {
		t.Fatal("function A record missing")
	}
	if len(functionA.Relationships) != 4 {
		t.Fatalf("function A placement edges = %d, want 4 (role + 2 subnets + security group)", len(functionA.Relationships))
	}
	if functionA.Resource.Attributes["vpc_config"] == nil {
		t.Fatal("function A vpc_config must be present")
	}

	functionB, ok := byID["aws_lambda_function\x00arn:aws:lambda:us-east-1:123456789012:function:wave1-b"]
	if !ok {
		t.Fatal("function B record missing")
	}
	if len(functionB.Relationships) != 0 {
		t.Fatalf("function B placement edges = %#v, want none", functionB.Relationships)
	}
	if value, present := functionB.Resource.Attributes["vpc_config"]; present && !reflect.DeepEqual(value, map[string]any(nil)) {
		t.Fatalf("function B vpc_config = %#v, want absent or nil", value)
	}
	if functionB.Resource.Attributes["last_modified"] != nil {
		t.Fatalf("function B last_modified = %#v, want nil (absent field)", functionB.Resource.Attributes["last_modified"])
	}
	if functionB.Resource.Tags != nil {
		t.Fatalf("function B tags = %#v, want nil", functionB.Resource.Tags)
	}
	if functionB.Resource.Attributes["image_uri"] != "123456789012.dkr.ecr.us-east-1.amazonaws.com/wave1/worker:prod" {
		t.Fatalf("function B image_uri = %#v", functionB.Resource.Attributes["image_uri"])
	}
	if functionB.Relationship == nil || functionB.Relationship.RelationshipType != "lambda_function_uses_image" {
		t.Fatalf("function B image relationship = %+v", functionB.Relationship)
	}

	staging, ok := byID["aws_lambda_alias\x00arn:aws:lambda:us-east-1:123456789012:function:wave1-a:staging"]
	if !ok {
		t.Fatal("ARN-less alias record missing")
	}
	if staging.Resource.ARN != "" {
		t.Fatalf("ARN-less alias ARN = %q, want empty", staging.Resource.ARN)
	}
	if staging.Relationship != nil {
		t.Fatalf("ARN-less alias relationship = %+v, want nil", staging.Relationship)
	}

	mappingB, ok := byID["aws_lambda_event_source_mapping\x0022222222-2222-3333-4444-555555555555"]
	if !ok {
		t.Fatal("UUID-only mapping record missing")
	}
	if mappingB.Resource.Attributes["function_arn"] != "arn:aws:lambda:us-east-1:123456789012:function:wave1-b" {
		t.Fatalf("UUID-only mapping function_arn = %#v, want parent fallback", mappingB.Resource.Attributes["function_arn"])
	}
	if mappingB.Relationship == nil || mappingB.Relationship.TargetResourceID != "arn:aws:lambda:us-east-1:123456789012:function:wave1-b" {
		t.Fatalf("UUID-only mapping relationship = %+v", mappingB.Relationship)
	}

	for _, record := range records {
		if record.Resource == nil {
			continue
		}
		encoded, err := json.Marshal(record.Resource.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "wave1-secret") {
			t.Fatalf("record %q leaks environment values: %s", record.Resource.ResourceID, encoded)
		}
	}
}

// TestWave1LambdaMappingAttributeEquality pins the mapping and placement
// attribute VALUES the stable-key parity cannot see: keys hash identity
// only, so a swapped batch_size/maximum_retry_attempts (or a wrong vpc_id)
// would pass every key gate. Expectations come straight from the fixture
// rows in testdata/wave1-lambda-parity.json.
func TestWave1LambdaMappingAttributeEquality(t *testing.T) {
	t.Parallel()

	fixture := loadWave1LambdaFixture(t)
	cfg := wave1LambdaStubConfig(t, fixture)
	records, err := listLambda(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	mappingA, ok := byID["aws_lambda_event_source_mapping\x00arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555"]
	if !ok {
		t.Fatal("mapping A record missing")
	}
	wantMappingA := map[string]any{
		"batch_size":             int32(10),
		"event_source_arn":       "arn:aws:sqs:us-east-1:123456789012:wave1-events",
		"function_arn":           "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
		"last_processing_result": "OK",
		"maximum_retry_attempts": int32(2),
		"parallelization_factor": int32(1),
		"starting_position":      "TRIM_HORIZON",
		"uuid":                   "11111111-2222-3333-4444-555555555555",
	}
	if !reflect.DeepEqual(mappingA.Resource.Attributes, wantMappingA) {
		t.Fatalf("mapping A attributes = %#v, want %#v", mappingA.Resource.Attributes, wantMappingA)
	}
	if mappingA.Relationship == nil {
		t.Fatal("mapping A relationship missing")
	}
	wantEdgeA := map[string]any{
		"event_source_arn": "arn:aws:sqs:us-east-1:123456789012:wave1-events",
		"state":            "Enabled",
		"uuid":             "11111111-2222-3333-4444-555555555555",
	}
	if !reflect.DeepEqual(mappingA.Relationship.Attributes, wantEdgeA) {
		t.Fatalf("mapping A edge attributes = %#v, want %#v", mappingA.Relationship.Attributes, wantEdgeA)
	}

	mappingB, ok := byID["aws_lambda_event_source_mapping\x0022222222-2222-3333-4444-555555555555"]
	if !ok {
		t.Fatal("UUID-only mapping record missing")
	}
	wantMappingB := map[string]any{
		"batch_size":             int32(0),
		"event_source_arn":       "arn:aws:kinesis:us-east-1:123456789012:stream/wave1-events",
		"function_arn":           "arn:aws:lambda:us-east-1:123456789012:function:wave1-b",
		"last_processing_result": "",
		"maximum_retry_attempts": int32(0),
		"parallelization_factor": int32(0),
		"starting_position":      "",
		"uuid":                   "22222222-2222-3333-4444-555555555555",
	}
	if !reflect.DeepEqual(mappingB.Resource.Attributes, wantMappingB) {
		t.Fatalf("mapping B attributes = %#v, want %#v", mappingB.Resource.Attributes, wantMappingB)
	}

	functionA, ok := byID["aws_lambda_function\x00arn:aws:lambda:us-east-1:123456789012:function:wave1-a"]
	if !ok {
		t.Fatal("function A record missing")
	}
	placements := map[string]map[string]any{}
	for _, edge := range functionA.Relationships {
		placements[edge.RelationshipType+"\x00"+edge.TargetResourceID] = edge.Attributes
	}
	wantPlacements := map[string]map[string]any{
		"lambda_function_uses_execution_role\x00arn:aws:iam::123456789012:role/wave1-lambda-role": nil,
		"lambda_function_uses_subnet\x00subnet-wave1a":                                            {"vpc_id": "vpc-wave1"},
		"lambda_function_uses_subnet\x00subnet-wave1b":                                            {"vpc_id": "vpc-wave1"},
		"lambda_function_uses_security_group\x00sg-wave1":                                         {"vpc_id": "vpc-wave1"},
	}
	if !reflect.DeepEqual(placements, wantPlacements) {
		t.Fatalf("function A placements = %#v, want %#v", placements, wantPlacements)
	}
}

// lambdaWave1Resource converts a live resource exactly as CollectReport does:
// the loader supplies identity, the claim triple is bound here in tests.
func lambdaWave1Resource(accountID string, resource *collector.LiveResource) collector.ResourceObservation {
	return collector.ResourceObservation{
		Boundary:           lambdaWave1Boundary(accountID, resource.Region, resource.ServiceKind),
		ARN:                resource.ARN,
		ResourceID:         resource.ResourceID,
		ResourceType:       resource.ResourceType,
		Name:               resource.Name,
		State:              resource.State,
		Tags:               resource.Tags,
		Attributes:         resource.Attributes,
		CorrelationAnchors: append([]string(nil), resource.CorrelationAnchors...),
		SourceRecordID:     resource.SourceRecordID,
		SourceURI:          "aws:lambda:us-east-1:wave1-parity",
	}
}

func lambdaWave1Relationship(accountID string, edge collector.LiveRelationship) collector.RelationshipObservation {
	observation := relationshipObservation(accountID, edge)
	observation.Boundary.ScopeID = "aws:123456789012:us-east-1"
	observation.Boundary.GenerationID = "aws:123456789012:us-east-1:wave1:1"
	observation.Boundary.CollectorInstanceID = "aws-parity-wave1"
	observation.Boundary.ClaimToken = "wave1-parity-token"
	observation.Boundary.ObservedAt = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	observation.SourceURI = "aws:lambda:us-east-1:wave1-parity"
	return observation
}

func lambdaWave1Boundary(accountID, region, serviceKind string) collector.Boundary {
	return collector.Boundary{
		AccountID: accountID, Region: region, ServiceKind: serviceKind,
		ScopeID:             "aws:123456789012:us-east-1",
		GenerationID:        "aws:123456789012:us-east-1:wave1:1",
		CollectorInstanceID: "aws-parity-wave1", FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}
