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

// TestWave1ECRParityAgainstInTreeOracle locks the completed ECR live emission
// to the in-tree oracle keys: every fact the in-tree Scanner.Scan derives for
// the shared fixture (testdata/wave1-ecr-parity.json) has a satellite twin
// with the identical stable key. The test drives the full production listECR
// path (stubbed ECR API: DescribeRepositories plus per-repository
// ListTagsForResource, DescribeImages, and GetLifecyclePolicy) and converts
// records to facts exactly as CollectReport does. Oracle keys come from the
// in-tree scan; the re-derivation recipe is in
// testdata/stable-key-provenance.md.
func TestWave1ECRParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1ECRFixture(t)
	cfg := wave1ECRStubConfig(t, fixture)
	records, err := listECR(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	const accountID = "123456789012"
	got := map[string]string{}
	for _, item := range records {
		if item.Relationship != nil || len(item.Relationships) != 0 {
			t.Fatalf("ECR record %q carries relationships, want none", item.ID)
		}
		if item.Resource != nil {
			fact, err := collector.NewResourceFact(ecrWave1Resource(accountID, item.Resource))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = item.Resource.ResourceID
		}
		if item.ImageReference != nil {
			fact, err := collector.NewImageReferenceFact(ecrWave1ImageReference(accountID, item.ImageReference))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = item.ImageReference.RepositoryName + "@" + item.ImageReference.ImageDigest + "#" + item.ImageReference.Tag
		}
	}

	want := []string{
		"aws_resource\x0068c5e90381f6f7687eb5007adc6e30cb589debe22efbdc0aaefceb25fae17cf6",
		"aws_image_reference\x002d65f7acf39ca991cbccd8efc347bf63dc4942a0a4394d555c68b6782f26d873",
		"aws_image_reference\x006928e0da143e0813c761afc4203f0ed8aefcdc0f3fe7866fc0d6f66dd7fff215",
		"aws_image_reference\x00235fb1889b0c527afc4a6e7bf1fada25936eb4b894998fdafd10e94a5bc9938d",
		"aws_resource\x0051e9ec1066630eb832a7194688996de9c219b732c8c939dd3629304246103cd5",
		"aws_resource\x00a47eb392133989c57ff28e619574607869af9681ff5583a2cb7207c870f5369a",
		"aws_image_reference\x00cf4129ff8f18d3c4d38a3e48e5254a6699960a0be141768112357f9be57f3a71",
		"aws_resource\x0036caf41fae08dce30ae039dbcad51bc1cb9134b6e16b0ebea2b8bd878b3f50dc",
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

// TestWave1ECRPayloadBranches pins the attribute branches stable keys cannot
// see: absent timestamps stay nil (not zero times), untagged rows stay nil
// (not empty maps), the untagged digest keeps one empty-tag reference, the
// never-evaluated policy keeps a nil evaluation time, and raw policy text
// never enters a fact. Values come straight from the fixture rows.
func TestWave1ECRPayloadBranches(t *testing.T) {
	t.Parallel()

	fixture := loadWave1ECRFixture(t)
	cfg := wave1ECRStubConfig(t, fixture)
	records, err := listECR(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	repositoryB, ok := byID["aws_ecr_repository\x00arn:aws:ecr:us-east-1:123456789012:repository/wave1-b"]
	if !ok {
		t.Fatal("repository B record missing")
	}
	if repositoryB.Resource.Attributes["created_at"] != nil {
		t.Fatalf("repository B created_at = %#v, want nil (absent field)", repositoryB.Resource.Attributes["created_at"])
	}
	if repositoryB.Resource.Tags != nil {
		t.Fatalf("repository B tags = %#v, want nil", repositoryB.Resource.Tags)
	}
	if repositoryB.Resource.Attributes["encryption_type"] != "" || repositoryB.Resource.Attributes["kms_key"] != "" {
		t.Fatalf("repository B encryption = %#v, want empty strings (absent block)",
			repositoryB.Resource.Attributes)
	}

	policyB, ok := byID["aws_ecr_lifecycle_policy\x00arn:aws:ecr:us-east-1:123456789012:repository/wave1-b#lifecycle-policy"]
	if !ok {
		t.Fatal("policy B record missing")
	}
	if policyB.Resource.Attributes["last_evaluated_at"] != nil {
		t.Fatalf("policy B last_evaluated_at = %#v, want nil (never evaluated)",
			policyB.Resource.Attributes["last_evaluated_at"])
	}

	untagged := 0
	for _, record := range records {
		if ref := record.ImageReference; ref != nil &&
			ref.ImageDigest == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
			untagged++
			if ref.Tag != "" {
				t.Fatalf("untagged image tag = %q, want empty", ref.Tag)
			}
		}
	}
	if untagged != 1 {
		t.Fatalf("untagged image references = %d, want 1", untagged)
	}

	for _, record := range records {
		if record.Resource == nil {
			continue
		}
		if _, exists := record.Resource.Attributes["policy_text"]; exists {
			t.Fatalf("record %q carries raw policy text", record.Resource.ResourceID)
		}
		encoded, err := json.Marshal(record.Resource.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "wave1-secret") {
			t.Fatalf("record %q leaks policy text values: %s", record.Resource.ResourceID, encoded)
		}
	}
}

// TestWave1ECRAttributeEquality pins the repository and policy attribute
// VALUES the stable-key parity cannot see: keys hash identity only, so a
// swapped encryption_type/image_tag_mutability (or a wrong repository_uri)
// would pass every key gate. Expectations come straight from the fixture
// rows in testdata/wave1-ecr-parity.json. The policy maps carry no
// policy_text by design: raw policy bodies can hold user-supplied values, so
// the satellite omits them where the in-tree scan emits them (locked by
// TestECRLifecyclePolicyMetadataOmitsPolicyText and documented in
// PORT_PLAN.md); the branches test above proves the omission end to end.
func TestWave1ECRAttributeEquality(t *testing.T) {
	t.Parallel()

	fixture := loadWave1ECRFixture(t)
	cfg := wave1ECRStubConfig(t, fixture)
	records, err := listECR(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	repositoryA, ok := byID["aws_ecr_repository\x00arn:aws:ecr:us-east-1:123456789012:repository/wave1-a"]
	if !ok {
		t.Fatal("repository A record missing")
	}
	wantRepositoryA := map[string]any{
		"created_at":           time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
		"encryption_type":      "KMS",
		"image_tag_mutability": "IMMUTABLE",
		"kms_key":              "arn:aws:kms:us-east-1:123456789012:key/wave1-key-1",
		"repository_uri":       "123456789012.dkr.ecr.us-east-1.amazonaws.com/wave1-a",
		"scan_on_push":         true,
	}
	if !reflect.DeepEqual(repositoryA.Resource.Attributes, wantRepositoryA) {
		t.Fatalf("repository A attributes = %#v, want %#v", repositoryA.Resource.Attributes, wantRepositoryA)
	}
	wantTagsA := map[string]string{"env": "wave1"}
	if !reflect.DeepEqual(repositoryA.Resource.Tags, wantTagsA) {
		t.Fatalf("repository A tags = %#v, want %#v", repositoryA.Resource.Tags, wantTagsA)
	}

	repositoryB, ok := byID["aws_ecr_repository\x00arn:aws:ecr:us-east-1:123456789012:repository/wave1-b"]
	if !ok {
		t.Fatal("repository B record missing")
	}
	wantRepositoryB := map[string]any{
		"created_at":           nil,
		"encryption_type":      "",
		"image_tag_mutability": "MUTABLE",
		"kms_key":              "",
		"repository_uri":       "123456789012.dkr.ecr.us-east-1.amazonaws.com/wave1-b",
		"scan_on_push":         false,
	}
	if !reflect.DeepEqual(repositoryB.Resource.Attributes, wantRepositoryB) {
		t.Fatalf("repository B attributes = %#v, want %#v", repositoryB.Resource.Attributes, wantRepositoryB)
	}

	policyA, ok := byID["aws_ecr_lifecycle_policy\x00arn:aws:ecr:us-east-1:123456789012:repository/wave1-a#lifecycle-policy"]
	if !ok {
		t.Fatal("policy A record missing")
	}
	wantPolicyA := map[string]any{
		"last_evaluated_at":      time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC),
		"parent_repository_arn":  "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
		"parent_repository_name": "wave1-a",
		"registry_id":            "123456789012",
	}
	if !reflect.DeepEqual(policyA.Resource.Attributes, wantPolicyA) {
		t.Fatalf("policy A attributes = %#v, want %#v", policyA.Resource.Attributes, wantPolicyA)
	}

	image := findWave1ECRImage(t, records,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "latest")
	wantImage := collector.LiveImageReference{
		Region: "us-east-1", ServiceKind: "ecr",
		RepositoryARN:  "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
		RepositoryName: "wave1-a", RegistryID: "123456789012",
		ImageDigest:       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tag:               "latest",
		PushedAt:          time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
		ImageSizeInBytes:  12345678,
		ManifestMediaType: "application/vnd.oci.image.manifest.v1+json",
		ArtifactMediaType: "application/vnd.oci.image.config.v1+json",
	}
	if !reflect.DeepEqual(*image, wantImage) {
		t.Fatalf("tagged image reference = %#v, want %#v", *image, wantImage)
	}
}

func findWave1ECRImage(t *testing.T, records []collector.Record, digest, tag string) *collector.LiveImageReference {
	t.Helper()
	for _, record := range records {
		if ref := record.ImageReference; ref != nil && ref.ImageDigest == digest && ref.Tag == tag {
			return ref
		}
	}
	t.Fatalf("image reference %s#%s missing", digest, tag)
	return nil
}

// ecrWave1Resource converts a live resource exactly as CollectReport does:
// the loader supplies identity, the claim triple is bound here in tests.
func ecrWave1Resource(accountID string, resource *collector.LiveResource) collector.ResourceObservation {
	return collector.ResourceObservation{
		Boundary:           ecrWave1Boundary(accountID, resource.Region, resource.ServiceKind),
		ARN:                resource.ARN,
		ResourceID:         resource.ResourceID,
		ResourceType:       resource.ResourceType,
		Name:               resource.Name,
		State:              resource.State,
		Tags:               resource.Tags,
		Attributes:         resource.Attributes,
		CorrelationAnchors: append([]string(nil), resource.CorrelationAnchors...),
		SourceRecordID:     resource.SourceRecordID,
		SourceURI:          "aws:ecr:us-east-1:wave1-parity",
	}
}

// ecrWave1ImageReference converts a live image reference exactly as
// CollectReport does: the loader supplies identity, the claim triple is bound
// here in tests.
func ecrWave1ImageReference(accountID string, ref *collector.LiveImageReference) collector.ImageReferenceObservation {
	return collector.ImageReferenceObservation{
		Boundary:          ecrWave1Boundary(accountID, ref.Region, ref.ServiceKind),
		RepositoryARN:     ref.RepositoryARN,
		RepositoryName:    ref.RepositoryName,
		RegistryID:        ref.RegistryID,
		ImageDigest:       ref.ImageDigest,
		ManifestDigest:    ref.ManifestDigest,
		Tag:               ref.Tag,
		PushedAt:          ref.PushedAt,
		ImageSizeInBytes:  ref.ImageSizeInBytes,
		ManifestMediaType: ref.ManifestMediaType,
		ArtifactMediaType: ref.ArtifactMediaType,
		SourceURI:         "aws:ecr:us-east-1:wave1-parity",
	}
}

func ecrWave1Boundary(accountID, region, serviceKind string) collector.Boundary {
	return collector.Boundary{
		AccountID: accountID, Region: region, ServiceKind: serviceKind,
		ScopeID:             "aws:123456789012:us-east-1",
		GenerationID:        "aws:123456789012:us-east-1:wave1:1",
		CollectorInstanceID: "aws-parity-wave1", FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}
