// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"strings"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// Security-group-rule source-kind discriminators. Each emitted
// aws_security_group_rule fact normalizes its rule target to exactly one of
// these so the reducer can project a single typed reachability edge per fact
// without re-deriving which target family a rule names. Values mirror the
// in-tree discriminators verbatim; the reducer keys on these strings.
const (
	// SecurityGroupRuleSourceCIDRIPv4 marks an IPv4 CIDR rule target.
	SecurityGroupRuleSourceCIDRIPv4 = "cidr_ipv4"
	// SecurityGroupRuleSourceCIDRIPv6 marks an IPv6 CIDR rule target.
	SecurityGroupRuleSourceCIDRIPv6 = "cidr_ipv6"
	// SecurityGroupRuleSourcePrefixList marks a managed-prefix-list rule target.
	SecurityGroupRuleSourcePrefixList = "prefix_list"
	// SecurityGroupRuleSourceSecurityGroup marks a referenced-security-group
	// rule target.
	SecurityGroupRuleSourceSecurityGroup = "referenced_security_group"
	// SecurityGroupRuleSourceUnknown marks a rule whose describe response carried
	// no CIDR, prefix list, or referenced group. It preserves the rule as
	// evidence instead of dropping it so the reducer can surface incomplete
	// posture rather than silently lose a rule.
	SecurityGroupRuleSourceUnknown = "unknown"
)

// Security-group-rule directions. The fact normalizes the AWS is_egress
// boolean to a stable string the reducer keys on.
const (
	// SecurityGroupRuleDirectionIngress marks an inbound rule.
	SecurityGroupRuleDirectionIngress = "ingress"
	// SecurityGroupRuleDirectionEgress marks an outbound rule.
	SecurityGroupRuleDirectionEgress = "egress"
)

// SecurityGroupRuleObservation describes one normalized EC2 security-group
// ingress or egress rule reported by DescribeSecurityGroupRules. It is the
// posture view of a rule: the scanner has already resolved the rule's single
// target family, so the observation carries one (SourceKind, SourceValue) pair
// rather than a bag of optional CIDR/prefix/group fields. Field-for-field it
// mirrors the in-tree observation so a shared fixture feeds both builders.
type SecurityGroupRuleObservation struct {
	Boundary       Boundary
	RuleID         string
	GroupID        string
	GroupOwnerID   string
	IsEgress       bool
	IPProtocol     string
	FromPort       *int32
	ToPort         *int32
	CIDRIPv4       string
	CIDRIPv6       string
	PrefixListID   string
	ReferencedSG   string
	Description    string
	SourceURI      string
	SourceRecordID string
}

// NewSecurityGroupRuleFact builds the durable aws_security_group_rule posture
// fact for one EC2 security-group rule. The fact is metadata-only: it carries
// identifiers, the protocol, the port range, and the normalized source, never
// a payload, secret, or policy body. Normalization mirrors the in-tree
// NewSecurityGroupRuleEnvelope verbatim so stable keys agree on shared input.
func NewSecurityGroupRuleFact(observation SecurityGroupRuleObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	groupID := strings.TrimSpace(observation.GroupID)
	if groupID == "" {
		return sdk.Fact{}, fmt.Errorf("aws security group rule observation requires group_id")
	}
	direction := securityGroupRuleDirection(observation.IsEgress)
	ipProtocol := strings.TrimSpace(observation.IPProtocol)
	sourceKind, sourceValue := normalizeSecurityGroupRuleSource(observation)
	ruleID := strings.TrimSpace(observation.RuleID)
	stableKey, err := specialtyStableKey(AWSKindSecurityGroupRule, map[string]any{
		"account_id":   observation.Boundary.AccountID,
		"direction":    direction,
		"from_port":    securityGroupPortValue(observation.FromPort),
		"group_id":     groupID,
		"ip_protocol":  ipProtocol,
		"region":       observation.Boundary.Region,
		"rule_id":      ruleID,
		"source_kind":  sourceKind,
		"source_value": sourceValue,
		"to_port":      securityGroupPortValue(observation.ToPort),
	})
	if err != nil {
		return sdk.Fact{}, err
	}
	payload, err := factschema.EncodeAWSSecurityGroupRule(awsv1.SecurityGroupRule{
		AccountID:           observation.Boundary.AccountID,
		Region:              observation.Boundary.Region,
		ServiceKind:         specialtyBoundaryValue(observation.Boundary.ServiceKind),
		CollectorInstanceID: specialtyBoundaryValue(observation.Boundary.CollectorInstanceID),
		RuleID:              specialtyStringPtr(ruleID),
		GroupID:             groupID,
		GroupOwnerID:        specialtyStringPtr(strings.TrimSpace(observation.GroupOwnerID)),
		Direction:           direction,
		IPProtocol:          ipProtocol,
		FromPort:            observation.FromPort,
		ToPort:              observation.ToPort,
		SourceKind:          sourceKind,
		SourceValue:         sourceValue,
		Description:         specialtyStringPtr(strings.TrimSpace(observation.Description)),
		IsInternet:          specialtyBoolPtr(isInternetSource(sourceKind, sourceValue)),
		IsAllProtocols:      specialtyBoolPtr(ipProtocol == securityGroupAllProtocols),
		IsAllPorts:          specialtyBoolPtr(isAllPorts(ipProtocol, observation.FromPort, observation.ToPort)),
		CorrelationAnchors:  securityGroupRuleAnchors(ruleID, groupID, sourceKind, sourceValue),
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws_security_group_rule payload: %w", err)
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = securityGroupRuleSourceID(groupID, direction, ipProtocol, sourceKind, sourceValue, observation)
	}
	return specialtyFact(AWSKindSecurityGroupRule, stableKey, observation.Boundary, observation.SourceURI, recordID, payload)
}

// securityGroupAllProtocols is the AWS IpProtocol value meaning "all
// protocols". AWS also leaves FromPort/ToPort unset for an all-protocols
// rule, so the fact derives is_all_ports from it as well.
const securityGroupAllProtocols = "-1"

const (
	securityGroupInternetCIDRIPv4 = "0.0.0.0/0"
	securityGroupInternetCIDRIPv6 = "::/0"
)

func securityGroupRuleDirection(isEgress bool) string {
	if isEgress {
		return SecurityGroupRuleDirectionEgress
	}
	return SecurityGroupRuleDirectionIngress
}

// normalizeSecurityGroupRuleSource collapses the rule's optional target fields
// into one (kind, value) pair, preferring the most specific target AWS would
// populate. The precedence only matters for malformed input; it stays
// deterministic so the stable key never flips for the same rule.
func normalizeSecurityGroupRuleSource(observation SecurityGroupRuleObservation) (string, string) {
	if value := strings.TrimSpace(observation.CIDRIPv4); value != "" {
		return SecurityGroupRuleSourceCIDRIPv4, value
	}
	if value := strings.TrimSpace(observation.CIDRIPv6); value != "" {
		return SecurityGroupRuleSourceCIDRIPv6, value
	}
	if value := strings.TrimSpace(observation.PrefixListID); value != "" {
		return SecurityGroupRuleSourcePrefixList, value
	}
	if value := strings.TrimSpace(observation.ReferencedSG); value != "" {
		return SecurityGroupRuleSourceSecurityGroup, value
	}
	return SecurityGroupRuleSourceUnknown, ""
}

// isInternetSource reports whether a rule's source opens the rule to the public
// internet. Only an exact open CIDR counts; a referenced group or prefix list
// is not internet exposure on its own.
func isInternetSource(sourceKind, sourceValue string) bool {
	switch sourceKind {
	case SecurityGroupRuleSourceCIDRIPv4:
		return sourceValue == securityGroupInternetCIDRIPv4
	case SecurityGroupRuleSourceCIDRIPv6:
		return sourceValue == securityGroupInternetCIDRIPv6
	default:
		return false
	}
}

// isAllPorts reports whether a rule spans every port. AWS encodes "all ports"
// either as the all-protocols sentinel or as an absent/explicit -1 port range.
func isAllPorts(ipProtocol string, fromPort, toPort *int32) bool {
	if ipProtocol == securityGroupAllProtocols {
		return true
	}
	return securityGroupPortCoversAll(fromPort) && securityGroupPortCoversAll(toPort)
}

func securityGroupPortCoversAll(port *int32) bool {
	return port == nil || *port == -1
}

// securityGroupPortValue renders an optional port for the stable key. A nil
// port (all-protocols rules omit the range) stays nil rather than collapsing
// to 0, which is a real port.
func securityGroupPortValue(port *int32) any {
	if port == nil {
		return nil
	}
	return *port
}

func securityGroupRuleAnchors(ruleID, groupID, sourceKind, sourceValue string) []string {
	anchors := []string{groupID}
	if ruleID != "" {
		anchors = append(anchors, ruleID)
	}
	if sourceKind == SecurityGroupRuleSourceSecurityGroup && sourceValue != "" {
		anchors = append(anchors, sourceValue)
	}
	return specialtyAnchors(nil, anchors...)
}

// securityGroupRuleSourceID builds the deterministic source record id used when
// AWS did not report a rule id (inline rules predating the rule-id era). It
// keys on the same identity the stable key uses so replays of the same rule
// resolve to one source record.
func securityGroupRuleSourceID(groupID, direction, ipProtocol, sourceKind, sourceValue string, observation SecurityGroupRuleObservation) string {
	if ruleID := strings.TrimSpace(observation.RuleID); ruleID != "" {
		return ruleID
	}
	parts := []string{
		groupID,
		direction,
		ipProtocol,
		fmt.Sprintf("%v", securityGroupPortValue(observation.FromPort)),
		fmt.Sprintf("%v", securityGroupPortValue(observation.ToPort)),
		sourceKind,
		sourceValue,
	}
	return strings.Join(parts, "#")
}
