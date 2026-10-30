// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// TestWave1EC2ExistingParityAgainstInTreeOracle locks the EC2 resource and
// relationship emission to the in-tree oracle keys: every aws_resource and
// aws_relationship fact the in-tree Scanner.Scan derives for the shared
// fixture (testdata/wave1-ec2-parity.json) has a satellite twin with the
// identical stable key. Oracle keys come from the in-tree scan; the
// re-derivation recipe is in testdata/stable-key-provenance.md. The companion
// gap test covers the four posture facts.
func TestWave1EC2ExistingParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	accountID := "123456789012"

	var resources []collector.ResourceObservation
	var relationships []collector.RelationshipObservation
	collectRecord := func(record collector.Record) {
		t.Helper()
		if record.Resource != nil {
			resources = append(resources, wave1ResourceObservation(t, accountID, record.Resource))
		}
		if record.Relationship != nil {
			relationships = append(relationships, wave1RelationshipObservation(t, accountID, *record.Relationship))
		}
		for _, edge := range record.Relationships {
			relationships = append(relationships, wave1RelationshipObservation(t, accountID, edge))
		}
	}

	collectRecord(vpcRecord(wave1SDKVPC(t, fixture), "us-east-1"))
	collectRecord(subnetRecord(wave1SDKSubnet(t, fixture), "us-east-1"))
	collectRecord(securityGroupRecord(wave1SDKSecurityGroup(t, fixture), "us-east-1"))
	for _, rule := range wave1SDKRules(t, fixture) {
		row, err := securityGroupRuleRecord(rule, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		collectRecord(row)
	}
	collectRecord(networkInterfaceRecord(wave1SDKNetworkInterface(t, fixture), "us-east-1", identity))
	instanceRecords, err := appendInstanceRecords(nil, wave1SDKInstance(t, fixture), "us-east-1", identity, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range instanceRecords {
		collectRecord(record)
	}
	collectRecord(volumeRecord(wave1SDKVolume(t, fixture), "us-east-1", identity))

	got := map[string]string{}
	for _, observation := range resources {
		fact, err := collector.NewResourceFact(observation)
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = observation.ResourceID
	}
	for _, observation := range relationships {
		fact, err := collector.NewRelationshipFact(observation)
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = observation.SourceRecordID
	}

	want := []string{
		"aws_resource\x0017f471132bc29990b36837ab30c388f7b8206c3cf8701bfa6ea126f0b365a2f8",
		"aws_resource\x00adaa5ade324f15fb97f3d500d7bd212d69fbb65a36204c041fb601e75fe768de",
		"aws_relationship\x00c4fed8da5d0bc3f7355074189f3e19de685c50434418e780389f136bf6c4b03e",
		"aws_resource\x0028c160045a039e8b569ec379b49b8e7e61700957aa2957fec7444db86561cbc9",
		"aws_relationship\x006f8ff0f2bb1de0f9733ddb17e55f05cce5af8a181f6325314ba1aabad88dc400",
		"aws_resource\x00b621175c9e3822d9a775125e8623fa2cf513d1ab3b26f5171b52104035045945",
		"aws_relationship\x009fc143989fdb07c5e4aff31764f22f6b4098ac4da860770f38077ea5f9f703fd",
		"aws_resource\x00a99604f42609e05d67cb38e197d1f5160afecd73ba452d3660eaf8be3bc6a480",
		"aws_relationship\x006e8c480b48b9c514b1b29e4b6f6d482dcefa57cb959367912775c7685a9b6979",
		"aws_resource\x005b84b35dbd6bdf089315c426b489cb4f84b0c5f3f4275da81648a66e084f3bb5",
		"aws_relationship\x00f4b077abca9ba48f8b7d3c1fc8be86ff1c8cd3236a43ddc675e0bba959e9779f",
		"aws_resource\x003e70715b86c89a8ab22d98de9321da98fa27558a5f28fe8056fa3dee9b849a0c",
		"aws_relationship\x00f4e7f9024d13785a7abc69fb54ce4d5091fb07d40cd6dfc3a6721984dc695678",
		"aws_relationship\x0068e87405a93f23ca4dc02e5564f149d7b78fa8f732670d3f147507514d36b080",
		"aws_relationship\x005e4b5ae77652cee885e3e99f5c9b4bcc74c6d15475b425e1a8d5842fb3129800",
		"aws_relationship\x0022614ae83911c01335f2fa516dece9fd6f3f82be7c7ddc2778cecaf561bb9168",
		"aws_resource\x00b3467e6df86a6c7484e93d8874df7dcff3c416e71487d6b3f663dafe22fec5ad",
		"aws_relationship\x0032b57dbc3bd9c05ff77e9ed8ba6c4ef9d878426526c7f1005a34e6f0a3531e5f",
		"aws_resource\x0083cdc1f7260f45a402b835c108b3c6ca6d9af7cfc4f3cbc2b8635f486ffbdb52",
		"aws_resource\x00347ea629dbebba6b9a7af6aa45c299bfd922bbda9232097b40528d7f07dfd905",
		"aws_relationship\x0036648f191e897893177aa08e14713af8d659095e49ec09a3b07f09f86f2abf20",
	}
	if len(got) != len(want) {
		t.Fatalf("parity fact count = %d, want %d", len(got), len(want))
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("missing oracle fact %q", key)
		}
	}
}

func wave1ResourceObservation(t *testing.T, accountID string, resource *collector.LiveResource) collector.ResourceObservation {
	t.Helper()
	observation := collector.ResourceObservation{
		Boundary:           wave1Boundary(accountID, resource.Region, resource.ServiceKind),
		ARN:                resource.ARN,
		ResourceID:         resource.ResourceID,
		ResourceType:       resource.ResourceType,
		Name:               resource.Name,
		State:              resource.State,
		Tags:               resource.Tags,
		Attributes:         resource.Attributes,
		CorrelationAnchors: append([]string(nil), resource.CorrelationAnchors...),
		SourceRecordID:     resource.SourceRecordID,
		SourceURI:          "aws:ec2:us-east-1:wave1-parity",
	}
	return observation
}

func wave1RelationshipObservation(t *testing.T, accountID string, edge collector.LiveRelationship) collector.RelationshipObservation {
	t.Helper()
	observation := relationshipObservation(accountID, edge)
	observation.Boundary.ScopeID = "aws:123456789012:us-east-1"
	observation.Boundary.GenerationID = "aws:123456789012:us-east-1:wave1:1"
	observation.Boundary.CollectorInstanceID = "aws-parity-wave1"
	observation.Boundary.ClaimToken = "wave1-parity-token"
	observation.Boundary.ObservedAt = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	observation.SourceURI = "aws:ec2:us-east-1:wave1-parity"
	return observation
}

func wave1Boundary(accountID, region, serviceKind string) collector.Boundary {
	return collector.Boundary{
		AccountID: accountID, Region: region, ServiceKind: serviceKind,
		ScopeID:             "aws:123456789012:us-east-1",
		GenerationID:        "aws:123456789012:us-east-1:wave1:1",
		CollectorInstanceID: "aws-parity-wave1", FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}
