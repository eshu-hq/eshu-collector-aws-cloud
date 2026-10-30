// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// TestWave1EKSParityAgainstInTreeOracle locks the completed EKS live emission
// to the in-tree oracle keys: every fact the in-tree Scanner.Scan derives for
// the shared fixture (testdata/wave1-eks-parity.json) has a satellite twin
// with the identical stable key. The test drives the full production listEKS
// path (stubbed EKS/IAM APIs, real OIDC matching, membership edges) and
// converts records to facts exactly as CollectReport does. Oracle keys come
// from the in-tree scan; the re-derivation recipe is in
// testdata/stable-key-provenance.md.
func TestWave1EKSParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EKSFixture(t)
	cfg := wave1EKSStubConfig(t, fixture)
	records, err := listEKS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}

	const accountID = "123456789012"
	got := map[string]string{}
	for _, item := range records {
		if edge := item.Relationship; edge != nil {
			fact, err := collector.NewRelationshipFact(eksWave1Relationship(accountID, *edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		for _, edge := range item.Relationships {
			fact, err := collector.NewRelationshipFact(eksWave1Relationship(accountID, edge))
			if err != nil {
				t.Fatal(err)
			}
			got[fact.Kind+"\x00"+fact.StableKey] = edge.SourceRecordID
		}
		if item.Resource == nil {
			continue
		}
		fact, err := collector.NewResourceFact(eksWave1Resource(accountID, item.Resource))
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = item.Resource.ResourceID
	}

	want := []string{
		"aws_resource\x00d93c4756992833aa00066fa0638331a76361a847e89a7827e3d1ba8bae2dd2f2",
		"aws_resource\x00a7fdc7bc6bf3bfe32de6028bd1afee39713e1a568c109d33bd7535a7c6649d6a",
		"aws_relationship\x00505f4fa7bb2296e04a55e2759429a1c4c12d255fc6eb51f0b3df4455033fd235",
		"aws_relationship\x00100f93c30b3aed52709f75e0d71b77b77fe608ce65f147b622b27a77d69fffe6",
		"aws_relationship\x001015e82159eecc4711c47cf36b0a9514ea9860a72f7628e389f7cf0ce7af137d",
		"aws_relationship\x00f427e3683f3181cef1c82e7af2dea2e3738ac81722567544bfaee24255896973",
		"aws_relationship\x00059886c7ecb7f829f9d1fe86fa8fceccf8305144dc10c5e7f5ecb49454ffb47d",
		"aws_relationship\x00dd88a0b26bec64f8a67b6a59014a14f25be8c4b277ae36448e62a8636bbbc561",
		"aws_resource\x00dd61effe0041ffa7025c1ba97800d4880e57452950d81eaccceca7d76c97ef46",
		"aws_relationship\x00b1855320125c01cc6aabd4e20c4edac2a9a226357d05045cfe2403a9624ad709",
		"aws_relationship\x00c6c2d00c3e494853f00a3b8c32969bddea2260036378d42ee44752b228e59191",
		"aws_relationship\x000398d17582bdf992068cd448c23c22b543f3a5f072da98d0f5c249bc9866954a",
		"aws_relationship\x00265d7ecd094462f7f4d61e72172dd2f36fc80892056215965139d371d70d60fa",
		"aws_resource\x000aea8263e32d251d70936ab516dc3c066fd39a16bf53d8fb5456934df76e2896",
		"aws_relationship\x0083d10cb7556c9ea55c6cfb565fc86462947914429855914981da9d793fef47f1",
		"aws_relationship\x00d73addbe76716d33edb7c74650eedbf40d138f221efac71928b34730ecbb2a64",
		"aws_resource\x0025332298be01cafacd5f11566de91a12657594da0ed1bc00747732bb5b4626f1",
		"aws_resource\x002f9c6c1fd60e0f755c6d0ad8a51f17dbce9de202ec2cb1266b7a80a195b83cd0",
		"aws_relationship\x00b9dcddd3f7e02a6e7f13975bf1aca50468fe7832d2b1bc5537658d96846012ca",
		"aws_relationship\x0003ef69c987803af2ca3287133b0ad083ca0945651b9a36e407058a389a94fabc",
		"aws_resource\x00cef21af4d704441f93e62d2509a07cab35ac5a3694f94c85698145f659760e34",
		"aws_relationship\x000e2d87b5c2fdbb75483e491078858aff9be1892c367094168b2cdbafaacfa04d",
		"aws_resource\x00d2fe294456e83c4f6f6ce005424f850fee94426a7004a788ac383e79cf17e98a",
		"aws_relationship\x00c5dfc76543b954d46014a54d21678c00373245361451eda2104d8a6e99c1db28",
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

// TestWave1EKSPayloadBranches pins the attribute branches stable keys cannot
// see: absent timestamps stay nil (not zero times), untagged rows stay nil
// (not empty maps), the unmatched provider stays issuer-only, and zero
// scaling keeps its int32 shape. Values come straight from the fixture rows.
func TestWave1EKSPayloadBranches(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EKSFixture(t)
	cfg := wave1EKSStubConfig(t, fixture)
	records, err := listEKS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceType+"\x00"+record.Resource.ResourceID] = record
		}
	}

	clusterB, ok := byID["aws_eks_cluster\x00arn:aws:eks:us-east-1:123456789012:cluster/wave1-b"]
	if !ok {
		t.Fatal("cluster B record missing")
	}
	if clusterB.Resource.Attributes["created_at"] != nil {
		t.Fatalf("cluster B created_at = %#v, want nil (absent field)", clusterB.Resource.Attributes["created_at"])
	}
	if clusterB.Resource.Tags != nil {
		t.Fatalf("cluster B tags = %#v, want nil", clusterB.Resource.Tags)
	}

	providerB, ok := byID["aws_eks_oidc_provider\x00https://oidc.eks.us-east-1.amazonaws.com/id/WAVE1BBB"]
	if !ok {
		t.Fatal("issuer-only provider record missing")
	}
	providerAttrs := providerB.Resource.Attributes
	if providerAttrs["issuer_url"] != "https://oidc.eks.us-east-1.amazonaws.com/id/WAVE1BBB" {
		t.Fatalf("issuer-only provider attrs = %#v", providerAttrs)
	}
	clientIDs, ok := providerAttrs["client_ids"].([]string)
	if !ok || clientIDs != nil {
		t.Fatalf("issuer-only client_ids = %#v, want nil slice", providerAttrs["client_ids"])
	}

	nodegroupB, ok := byID["aws_eks_nodegroup\x00arn:aws:eks:us-east-1:123456789012:nodegroup/wave1-b/ng-b1/66666666-7777-8888-9999-000000000000"]
	if !ok {
		t.Fatal("nodegroup B record missing")
	}
	scaling, ok := nodegroupB.Resource.Attributes["scaling_config"].(map[string]any)
	if !ok || scaling["desired_size"] != int32(0) || scaling["min_size"] != int32(0) || scaling["max_size"] != int32(0) {
		t.Fatalf("nodegroup B scaling = %#v, want int32 zeros", nodegroupB.Resource.Attributes["scaling_config"])
	}

	addonB, ok := byID["aws_eks_addon\x00arn:aws:eks:us-east-1:123456789012:addon/wave1-b/coredns/ffffffff-0000-1111-2222-333333333333"]
	if !ok {
		t.Fatal("addon B record missing")
	}
	if addonB.Resource.Attributes["created_at"] != nil || addonB.Resource.Attributes["modified_at"] != nil {
		t.Fatalf("addon B timestamps = %#v %#v, want nil",
			addonB.Resource.Attributes["created_at"], addonB.Resource.Attributes["modified_at"])
	}
}

// eksWave1Resource converts a live resource exactly as CollectReport does:
// the loader supplies identity, the claim triple is bound here in tests.
func eksWave1Resource(accountID string, resource *collector.LiveResource) collector.ResourceObservation {
	return collector.ResourceObservation{
		Boundary:           eksWave1Boundary(accountID, resource.Region, resource.ServiceKind),
		ARN:                resource.ARN,
		ResourceID:         resource.ResourceID,
		ResourceType:       resource.ResourceType,
		Name:               resource.Name,
		State:              resource.State,
		Tags:               resource.Tags,
		Attributes:         resource.Attributes,
		CorrelationAnchors: append([]string(nil), resource.CorrelationAnchors...),
		SourceRecordID:     resource.SourceRecordID,
		SourceURI:          "aws:eks:us-east-1:wave1-parity",
	}
}

func eksWave1Relationship(accountID string, edge collector.LiveRelationship) collector.RelationshipObservation {
	observation := relationshipObservation(accountID, edge)
	observation.Boundary.ScopeID = "aws:123456789012:us-east-1"
	observation.Boundary.GenerationID = "aws:123456789012:us-east-1:wave1:1"
	observation.Boundary.CollectorInstanceID = "aws-parity-wave1"
	observation.Boundary.ClaimToken = "wave1-parity-token"
	observation.Boundary.ObservedAt = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	observation.SourceURI = "aws:eks:us-east-1:wave1-parity"
	return observation
}

func eksWave1Boundary(accountID, region, serviceKind string) collector.Boundary {
	return collector.Boundary{
		AccountID: accountID, Region: region, ServiceKind: serviceKind,
		ScopeID:             "aws:123456789012:us-east-1",
		GenerationID:        "aws:123456789012:us-east-1:wave1:1",
		CollectorInstanceID: "aws-parity-wave1", FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}
