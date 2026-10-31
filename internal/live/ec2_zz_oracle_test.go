// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"reflect"
	"strings"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// TestZZEC2OracleAnchorAndEdgeParity is the independent byte-level oracle for
// the Lane-0 EC2 scope (PORT_PLAN.md ordering step 4): every EC2 resource and
// relationship the satellite derives from the shared wave-1 fixture must carry
// the exact correlation anchors (order-sensitive), source record IDs, and
// edge tuples the in-tree scanner emits for the same rows.
//
// Expectations below are re-derived from the in-tree source, not from the
// satellite builders:
//   - service/ec2/scanner.go: vpcObservation, subnetObservation,
//     securityGroupObservation, securityGroupRuleObservation (anchors are
//     [resource_id, group-or-arn secondaries]),
//     networkInterfaceObservation, securityGroupRuleID fallback;
//   - service/ec2/identity.go: instanceIdentityObservation anchors
//     [resourceID, arn] (resource id FIRST), instanceAMIRelationship tuple;
//   - service/ec2/ami_identity.go: amiResourceObservation anchors [amiID];
//   - service/ec2/volume.go: volumeObservation anchors [arn, id],
//     volumeKMSRelationship tuple;
//   - service/ec2/relationships.go: subnet/VPC, group/VPC, rule, ENI, and
//     attachment edge tuples and "#"-joined source record IDs;
//   - awscloud/envelope.go normalizedAnchors: explicit values first, then the
//     (arn, resource_id) fallback, blank and duplicate entries dropped.
//
// The satellite seam (resource_envelope.go normalizedResourceAnchors) applies
// the same fallback, so builders that set no explicit anchors must still emit
// the fallback order. A mismatch here means the emitted fact payload differs
// byte-for-byte from the in-tree twin even though the stable keys match.
func TestZZEC2OracleAnchorAndEdgeParity(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	accountID := "123456789012"

	instanceARN := "arn:aws:ec2:us-east-1:123456789012:instance/i-wave1"
	subnetARN := "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-wave1"
	volumeARN := "arn:aws:ec2:us-east-1:123456789012:volume/vol-wave1"
	kmsKeyID := "arn:aws:kms:us-east-1:123456789012:key/wave1key"

	type resourceCase struct {
		name     string
		record   collector.Record
		anchors  []string
		recordID string
	}
	rules := wave1SDKRules(t, fixture)
	ruleRows := make([]collector.Record, 0, len(rules))
	for _, rule := range rules {
		row, err := securityGroupRuleRecord(rule, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		ruleRows = append(ruleRows, row)
	}
	instanceRows, err := appendInstanceRecords(nil, wave1SDKInstance(t, fixture), "us-east-1", identity, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []resourceCase{
		{
			"vpc", vpcRecord(wave1SDKVPC(t, fixture), "us-east-1"),
			[]string{"vpc-wave1"},
			"vpc-wave1",
		},
		{
			"subnet", subnetRecord(wave1SDKSubnet(t, fixture), "us-east-1"),
			[]string{subnetARN, "subnet-wave1"},
			"subnet-wave1",
		},
		{
			"security-group", securityGroupRecord(wave1SDKSecurityGroup(t, fixture), "us-east-1"),
			[]string{"sg-wave1", "wave1-web"},
			"sg-wave1",
		},
		{
			"rule-cidr", ruleRows[0],
			[]string{"sgr-wave1a", "sg-wave1"},
			"sgr-wave1a",
		},
		{
			"rule-referenced", ruleRows[2],
			[]string{"sgr-wave1c", "sg-wave1"},
			"sgr-wave1c",
		},
		{
			"network-interface", networkInterfaceRecord(wave1SDKNetworkInterface(t, fixture), "us-east-1", identity),
			[]string{"eni-wave1"},
			"eni-wave1",
		},
		{
			"instance", instanceRows[0],
			[]string{"i-wave1", instanceARN},
			"i-wave1",
		},
		{
			"ami", instanceRows[1],
			[]string{"ami-wave1"},
			"ami-wave1",
		},
		{
			"volume", volumeRecord(wave1SDKVolume(t, fixture), "us-east-1", identity),
			[]string{volumeARN, "vol-wave1"},
			"vol-wave1",
		},
	}
	for _, tc := range cases {
		if tc.record.Resource == nil {
			t.Fatalf("%s: typed resource missing", tc.name)
		}
		observation := wave1ResourceObservation(t, accountID, tc.record.Resource)
		fact, err := collector.NewResourceFact(observation)
		if err != nil {
			t.Fatal(err)
		}
		if got := oracleAnchors(t, fact.Payload); !reflect.DeepEqual(got, tc.anchors) {
			t.Errorf("%s: correlation anchors = %#v, want %#v", tc.name, got, tc.anchors)
		}
		if fact.SourceRef.RecordID != tc.recordID {
			t.Errorf("%s: source record id = %q, want %q", tc.name, fact.SourceRef.RecordID, tc.recordID)
		}
	}

	// The legacy no-ID rule keeps the parity property anchors[0] == resource_id
	// with the group anchor second, whatever the fallback hash reads.
	fallbackRow := ruleRows[1]
	fallbackObservation := wave1ResourceObservation(t, accountID, fallbackRow.Resource)
	fallbackFact, err := collector.NewResourceFact(fallbackObservation)
	if err != nil {
		t.Fatal(err)
	}
	fallbackAnchors := oracleAnchors(t, fallbackFact.Payload)
	if len(fallbackAnchors) != 2 || fallbackAnchors[0] != fallbackRow.Resource.ResourceID || fallbackAnchors[1] != "sg-wave1" {
		t.Errorf("rule-fallback anchors = %#v, want [resource-id sg-wave1]", fallbackAnchors)
	}
	if !strings.HasPrefix(fallbackAnchors[0], "security-group-rule:") {
		t.Errorf("rule-fallback id = %q, want security-group-rule: prefix", fallbackAnchors[0])
	}

	type edgeCase struct {
		name       string
		edge       collector.LiveRelationship
		relType    string
		sourceID   string
		sourceARN  string
		targetID   string
		targetARN  string
		targetType string
		recordID   string
		attributes map[string]any
	}
	eniEdges := networkInterfaceRecord(wave1SDKNetworkInterface(t, fixture), "us-east-1", identity).Relationships
	edges := []edgeCase{
		{
			"subnet-in-vpc", *subnetRecord(wave1SDKSubnet(t, fixture), "us-east-1").Relationship,
			"ec2_subnet_in_vpc", "subnet-wave1", subnetARN, "vpc-wave1", "", "aws_ec2_vpc",
			"subnet-wave1#vpc#vpc-wave1", nil,
		},
		{
			"group-in-vpc", *securityGroupRecord(wave1SDKSecurityGroup(t, fixture), "us-east-1").Relationship,
			"ec2_security_group_in_vpc", "sg-wave1", "", "vpc-wave1", "", "aws_ec2_vpc",
			"sg-wave1#vpc#vpc-wave1", nil,
		},
		{
			"group-has-rule", *ruleRows[0].Relationship,
			"ec2_security_group_has_rule", "sg-wave1", "", "sgr-wave1a", "", "aws_ec2_security_group_rule",
			"sg-wave1#rule#sgr-wave1a",
			map[string]any{"direction": "ingress"},
		},
		{
			"eni-in-subnet", eniEdges[0],
			"ec2_network_interface_in_subnet", "eni-wave1", "", "subnet-wave1", "", "aws_ec2_subnet",
			"eni-wave1#subnet#subnet-wave1", nil,
		},
		{
			"eni-in-vpc", eniEdges[1],
			"ec2_network_interface_in_vpc", "eni-wave1", "", "vpc-wave1", "", "aws_ec2_vpc",
			"eni-wave1#vpc#vpc-wave1", nil,
		},
		{
			"eni-uses-sg", eniEdges[2],
			"ec2_network_interface_uses_security_group", "eni-wave1", "", "sg-wave1", "", "aws_ec2_security_group",
			"eni-wave1#security-group#sg-wave1",
			map[string]any{"group_name": "wave1-web"},
		},
		{
			"eni-attached", eniEdges[3],
			"ec2_network_interface_attached_to_resource", "eni-wave1", "", "i-wave1", instanceARN, "aws_ec2_instance",
			"eni-wave1#attachment#i-wave1", nil,
		},
		{
			"instance-uses-ami", *instanceRows[0].Relationship,
			"ec2_instance_uses_ami", "i-wave1", instanceARN, "ami-wave1", "", "aws_ec2_ami",
			"i-wave1#ami#ami-wave1", nil,
		},
		{
			"volume-uses-kms", *volumeRecord(wave1SDKVolume(t, fixture), "us-east-1", identity).Relationship,
			"ec2_volume_uses_kms_key", "vol-wave1", volumeARN, kmsKeyID, kmsKeyID, "aws_kms_key",
			"vol-wave1#kms#" + kmsKeyID, nil,
		},
	}
	for _, tc := range edges {
		observation := wave1RelationshipObservation(t, accountID, tc.edge)
		fact, err := collector.NewRelationshipFact(observation)
		if err != nil {
			t.Fatal(err)
		}
		payload := fact.Payload
		if tc.edge.RelationshipType != tc.relType ||
			tc.edge.SourceResourceID != tc.sourceID ||
			tc.edge.SourceARN != tc.sourceARN ||
			tc.edge.TargetResourceID != tc.targetID ||
			tc.edge.TargetARN != tc.targetARN ||
			tc.edge.TargetType != tc.targetType ||
			tc.edge.SourceRecordID != tc.recordID {
			t.Errorf("%s: edge = %#v, want type=%q src=%q/%q tgt=%q/%q/%q record=%q",
				tc.name, tc.edge, tc.relType, tc.sourceID, tc.sourceARN,
				tc.targetID, tc.targetARN, tc.targetType, tc.recordID)
		}
		if tc.attributes != nil && !reflect.DeepEqual(mapOf(payload, "attributes"), tc.attributes) {
			t.Errorf("%s: edge attributes = %#v, want %#v", tc.name, mapOf(payload, "attributes"), tc.attributes)
		}
		if fact.SourceRef.RecordID != tc.recordID {
			t.Errorf("%s: edge source record id = %q, want %q", tc.name, fact.SourceRef.RecordID, tc.recordID)
		}
	}
}

// oracleAnchors reads the emitted correlation_anchors payload array back into
// an order-preserving string slice; a nil payload array reads back as nil so
// an anchorless fact cannot pass an anchored expectation.
func oracleAnchors(t *testing.T, payload map[string]any) []string {
	t.Helper()
	raw, ok := payload["correlation_anchors"]
	if !ok || raw == nil {
		return nil
	}
	if values, ok := raw.([]string); ok {
		return append([]string(nil), values...)
	}
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("correlation_anchors = %#v, want array", raw)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok {
			t.Fatalf("correlation anchor = %#v, want string", item)
		}
		out = append(out, value)
	}
	return out
}

func mapOf(payload map[string]any, key string) map[string]any {
	raw, ok := payload[key]
	if !ok || raw == nil {
		return nil
	}
	out, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	return out
}
