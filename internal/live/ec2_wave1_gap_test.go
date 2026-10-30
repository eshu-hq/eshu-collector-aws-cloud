// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// TestWave1EC2GapParityAgainstInTreeOracle proves the Wave 1 EC2 completion:
// the in-tree Scanner.Scan emits one aws_security_group_rule posture fact per
// rule and one ec2_instance_posture fact per instance, and the satellite live
// path now emits all four with identical stable keys on the shared fixture.
// (The companion parity test covers every resource and relationship key; the
// edge unit tests below pin the new edge shapes.) This test fails until the
// posture channel exists: the record builders carry no posture observations.
func TestWave1EC2GapParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	accountID := "123456789012"

	var sgPostures []collector.SecurityGroupRuleObservation
	var ec2Postures []collector.EC2InstancePostureObservation

	for _, rule := range wave1SDKRules(t, fixture) {
		row, err := securityGroupRuleRecord(rule, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		if row.SGPosture == nil {
			t.Fatal("security group rule record carries no posture observation")
		}
		posture := *row.SGPosture
		posture.Boundary = wave1Boundary(accountID, "us-east-1", "ec2")
		posture.SourceURI = "aws:ec2:us-east-1:wave1-parity"
		sgPostures = append(sgPostures, posture)
	}

	instanceRecords, err := appendInstanceRecords(nil, wave1SDKInstance(t, fixture), "us-east-1", identity, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range instanceRecords {
		if record.Resource != nil && record.Resource.ResourceType == "aws_ec2_instance" && record.EC2Posture == nil {
			t.Fatal("instance record carries no posture observation")
		}
		if record.EC2Posture != nil {
			posture := *record.EC2Posture
			posture.Boundary = wave1Boundary(accountID, "us-east-1", "ec2")
			posture.SourceURI = "aws:ec2:us-east-1:wave1-parity"
			ec2Postures = append(ec2Postures, posture)
		}
	}

	got := map[string]bool{}
	for _, observation := range sgPostures {
		fact, err := collector.NewSecurityGroupRuleFact(observation)
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = true
	}
	for _, observation := range ec2Postures {
		fact, err := collector.NewEC2InstancePostureFact(observation)
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = true
	}

	want := []string{
		"aws_security_group_rule\x00d4373b5d54f28e24d86164a999d1b4413957f5725e869980ef33d1ae57c88c8b",
		"aws_security_group_rule\x00828bdb8d4b4842d4c75dc70aae4fb53f6d658ec6a957f8322fbebdeed5e2e3dd",
		"aws_security_group_rule\x0031dc36fc0dd0fee06cbadcdb51fffbe36932a1a178731c638044840aebe7e126",
		"ec2_instance_posture\x00bccfe99d717602531c9eeb0ac1889236f16e0924ffc40b66ff8fefee72e81b04",
	}
	if len(got) != len(want) {
		t.Fatalf("gap fact count = %d, want %d", len(got), len(want))
	}
	for _, key := range want {
		if !got[key] {
			t.Errorf("missing oracle fact %q", key)
		}
	}
}

// TestSecurityGroupRecordCarriesVPCEdge locks the group->VPC edge the in-tree
// scanner emits alongside every security-group resource fact.
func TestSecurityGroupRecordCarriesVPCEdge(t *testing.T) {
	t.Parallel()

	group := securityGroupRecord(wave1SDKSecurityGroup(t, loadWave1EC2Fixture(t)), "us-east-1")
	edge := group.Relationship
	if edge == nil {
		t.Fatal("security group record carries no VPC edge")
	}
	if edge.RelationshipType != "ec2_security_group_in_vpc" || edge.SourceResourceID != "sg-wave1" ||
		edge.TargetResourceID != "vpc-wave1" || edge.TargetType != "aws_ec2_vpc" ||
		edge.SourceRecordID != "sg-wave1#vpc#vpc-wave1" {
		t.Fatalf("security group VPC edge = %#v", edge)
	}

	bare := ec2types.SecurityGroup{GroupId: aws.String("sg-bare")}
	if got := securityGroupRecord(bare, "us-east-1"); got.Relationship != nil {
		t.Fatalf("group without VPC emitted edge = %#v", got.Relationship)
	}
}

// TestSecurityGroupRuleRecordCarriesGroupEdge locks the rule->group edge the
// in-tree scanner emits alongside every rule resource fact, including the
// direction attribute and the legacy fallback identity.
func TestSecurityGroupRuleRecordCarriesGroupEdge(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	rules := wave1SDKRules(t, fixture)
	if len(rules) != 3 {
		t.Fatalf("fixture rule count = %d, want 3", len(rules))
	}
	for i, rule := range rules {
		row, err := securityGroupRuleRecord(rule, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		edge := row.Relationship
		if edge == nil {
			t.Fatalf("rule %d record carries no group edge", i)
		}
		if edge.RelationshipType != "ec2_security_group_has_rule" ||
			edge.SourceResourceID != "sg-wave1" || edge.TargetType != "aws_ec2_security_group_rule" {
			t.Fatalf("rule %d group edge = %#v", i, edge)
		}
		wantDirection := "ingress"
		if i == 1 {
			wantDirection = "egress"
		}
		if edge.Attributes["direction"] != wantDirection {
			t.Fatalf("rule %d edge direction = %#v, want %q", i, edge.Attributes["direction"], wantDirection)
		}
	}
}

// TestSecurityGroupRulePostureObservation locks the posture mapping for the
// three fixture rules: plain CIDR, legacy no-ID fallback, referenced group.
func TestSecurityGroupRulePostureObservation(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	rules := wave1SDKRules(t, fixture)

	first := securityGroupRulePosture(rules[0], "us-east-1")
	if first.RuleID != "sgr-wave1a" || first.GroupID != "sg-wave1" ||
		first.GroupOwnerID != "123456789012" || first.IsEgress ||
		first.IPProtocol != "tcp" || first.CIDRIPv4 != "0.0.0.0/0" ||
		first.Description != "wave1 https" || first.ReferencedSG != "" {
		t.Fatalf("cidr rule posture = %#v", first)
	}
	if first.FromPort == nil || *first.FromPort != 443 || first.ToPort == nil || *first.ToPort != 443 {
		t.Fatalf("cidr rule posture ports = %#v %#v", first.FromPort, first.ToPort)
	}

	fallback := securityGroupRulePosture(rules[1], "us-east-1")
	if fallback.RuleID != "" || fallback.GroupID != "sg-wave1" || !fallback.IsEgress ||
		fallback.IPProtocol != "-1" || fallback.PrefixListID != "pl-wave1" {
		t.Fatalf("fallback rule posture = %#v", fallback)
	}
	if fallback.FromPort != nil || fallback.ToPort != nil {
		t.Fatalf("fallback rule posture ports = %#v %#v, want nil", fallback.FromPort, fallback.ToPort)
	}

	peer := securityGroupRulePosture(rules[2], "us-east-1")
	if peer.RuleID != "sgr-wave1c" || peer.ReferencedSG != "sg-wave1-peer" ||
		peer.CIDRIPv4 != "" || peer.CIDRIPv6 != "" {
		t.Fatalf("referenced-group rule posture = %#v", peer)
	}
}

// TestInstancePostureObservation locks the DescribeInstances-row mapping the
// in-tree mapper performs: metadata-only fields only, presence booleans stay
// nil when the control plane reports nothing, user-data content never read.
func TestInstancePostureObservation(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	posture := instancePostureObservation(
		wave1SDKInstance(t, fixture), "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"},
	)
	if posture.ARN != "arn:aws:ec2:us-east-1:123456789012:instance/i-wave1" ||
		posture.InstanceID != "i-wave1" || posture.State != "running" {
		t.Fatalf("posture identity = %#v", posture)
	}
	if posture.IMDSv2Required == nil || !*posture.IMDSv2Required ||
		posture.HTTPEndpoint != "enabled" ||
		posture.HTTPPutResponseHopLimit == nil || *posture.HTTPPutResponseHopLimit != 2 {
		t.Fatalf("posture IMDS = %#v %#v %#v", posture.IMDSv2Required, posture.HTTPEndpoint, posture.HTTPPutResponseHopLimit)
	}
	if posture.UserDataPresent != nil {
		t.Fatalf("posture user-data presence = %#v, want nil (content never read)", posture.UserDataPresent)
	}
	if !posture.DetailedMonitoring || !posture.EBSOptimized || !posture.PublicIPAssociated ||
		posture.PublicIPAddress != "203.0.113.7" ||
		posture.InstanceProfileARN != "arn:aws:iam::123456789012:instance-profile/wave1" ||
		posture.Tenancy != "default" || posture.NitroEnclaveEnabled {
		t.Fatalf("posture operations = %#v", posture)
	}
	if len(posture.BlockDevices) != 1 {
		t.Fatalf("posture block devices = %#v, want one", posture.BlockDevices)
	}
	device := posture.BlockDevices[0]
	if device.DeviceName != "/dev/sda1" || device.VolumeID != "vol-wave1" ||
		!device.DeleteOnTermination || device.Status != "attached" || device.Encrypted != nil {
		t.Fatalf("posture block device = %#v", device)
	}
	if posture.SourceRecordID != "i-wave1" {
		t.Fatalf("posture source record = %q, want instance id", posture.SourceRecordID)
	}
}
