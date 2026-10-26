// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package route53resolver

import (
	"testing"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func testBoundary() awscloud.Boundary {
	return awscloud.Boundary{
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ServiceKind:  catalog.ServiceRoute53Resolver,
		ScopeID:      "scope-1",
		GenerationID: "gen-1",
	}
}

// TestPortParity_EndpointInVPCAndSubnets freezes the endpoint edges: the VPC
// edge carries the direction attribute and subnet IDs are de-duplicated.
func TestPortParity_EndpointInVPCAndSubnets(t *testing.T) {
	t.Parallel()
	endpoint := ResolverEndpoint{
		ID:        "rslvr-in-1",
		Direction: "INBOUND",
		HostVPCID: "vpc-1",
		SubnetIDs: []string{"subnet-1", "subnet-1", " ", "subnet-2"},
	}
	got := endpointRelationships(testBoundary(), endpoint)
	if len(got) != 3 {
		t.Fatalf("endpointRelationships() = %#v, want 3 edges (vpc + 2 subnets)", got)
	}
	vpc := got[0]
	if vpc.RelationshipType != catalog.RelationshipRoute53ResolverEndpointInVPC ||
		vpc.TargetType != catalog.ResourceTypeEC2VPC ||
		vpc.Attributes["direction"] != "INBOUND" ||
		vpc.SourceRecordID != "rslvr-in-1#vpc#vpc-1" {
		t.Fatalf("vpc edge = %#v", vpc)
	}
	if got[1].TargetResourceID != "subnet-1" || got[2].TargetResourceID != "subnet-2" {
		t.Fatalf("subnet edges = %#v", got[1:])
	}
	if got := endpointRelationships(testBoundary(), ResolverEndpoint{}); got != nil {
		t.Fatalf("empty endpoint = %#v, want nil", got)
	}
}

// TestPortParity_RuleUsesEndpoint freezes the rule edge and the
// endpoint-absent nil contract.
func TestPortParity_RuleUsesEndpoint(t *testing.T) {
	t.Parallel()
	rule := ResolverRule{ID: "rslvr-rr-1", RuleType: "FORWARD", ResolverEndpointID: "rslvr-in-1"}
	got := ruleRelationships(testBoundary(), rule)
	if len(got) != 1 {
		t.Fatalf("ruleRelationships() = %#v, want 1 edge", got)
	}
	edge := got[0]
	if edge.TargetType != catalog.ResourceTypeRoute53ResolverEndpoint ||
		edge.Attributes["rule_type"] != "FORWARD" ||
		edge.SourceRecordID != "rslvr-rr-1#endpoint#rslvr-in-1" {
		t.Fatalf("rule edge = %#v", edge)
	}
	if got := ruleRelationships(testBoundary(), ResolverRule{ID: "r", ResolverEndpointID: " "}); got != nil {
		t.Fatalf("endpoint-absent rule = %#v, want nil", got)
	}
}

// TestPortParity_AssociationTargets freezes the association fan-out: VPC and
// rule edges only when their IDs are present.
func TestPortParity_AssociationTargets(t *testing.T) {
	t.Parallel()
	assoc := ResolverRuleAssociation{ID: "rslvr-ra-1", ResolverRuleID: "rslvr-rr-1", VPCID: "vpc-1"}
	got := ruleAssociationRelationships(testBoundary(), assoc)
	if len(got) != 2 {
		t.Fatalf("ruleAssociationRelationships() = %#v, want 2 edges", got)
	}
	if got[0].TargetResourceID != "vpc-1" || got[1].TargetResourceID != "rslvr-rr-1" {
		t.Fatalf("association edges = %#v", got)
	}
	bare := ResolverRuleAssociation{ID: "rslvr-ra-2"}
	if got := ruleAssociationRelationships(testBoundary(), bare); got != nil {
		t.Fatalf("id-only association = %#v, want nil", got)
	}
	fw := FirewallRuleGroupAssociation{ID: "rslvr-fassoc-1", FirewallRuleGroupID: "rslvr-frg-1", VPCID: "vpc-1"}
	fgot := firewallRuleGroupAssociationRelationships(testBoundary(), fw)
	if len(fgot) != 2 || fgot[1].TargetType != catalog.ResourceTypeRoute53ResolverFirewallRuleGroup {
		t.Fatalf("firewall association edges = %#v", fgot)
	}
}
