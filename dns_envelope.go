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

// NewDNSRecordFact builds the durable aws_dns_record fact for one Route 53
// DNS record observation. It mirrors the in-tree NewDNSRecordEnvelope
// normalization verbatim (record-type upper-casing, trailing-dot-insensitive
// name keying, set-identifier-scoped identity) so the shared fixture yields
// the same stable key on both sides.
func NewDNSRecordFact(observation DNSRecordObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	hostedZoneID := strings.TrimSpace(observation.HostedZoneID)
	recordName := strings.TrimSpace(observation.RecordName)
	recordType := strings.ToUpper(strings.TrimSpace(observation.RecordType))
	if hostedZoneID == "" {
		return sdk.Fact{}, fmt.Errorf("aws dns record observation requires hosted_zone_id")
	}
	if recordName == "" {
		return sdk.Fact{}, fmt.Errorf("aws dns record observation requires record_name")
	}
	if recordType == "" {
		return sdk.Fact{}, fmt.Errorf("aws dns record observation requires record_type")
	}
	normalizedRecordName := normalizeDNSName(recordName)
	setIdentifier := strings.TrimSpace(observation.SetIdentifier)
	stableKey, err := specialtyStableKey(AWSKindDNSRecord, map[string]any{
		"account_id":             observation.Boundary.AccountID,
		"hosted_zone_id":         hostedZoneID,
		"normalized_record_name": normalizedRecordName,
		"record_type":            recordType,
		"region":                 observation.Boundary.Region,
		"set_identifier":         setIdentifier,
	})
	if err != nil {
		return sdk.Fact{}, err
	}
	payload, err := factschema.EncodeAWSDNSRecord(awsv1.DNSRecord{
		AccountID:            observation.Boundary.AccountID,
		Region:               observation.Boundary.Region,
		ServiceKind:          specialtyBoundaryValue(observation.Boundary.ServiceKind),
		CollectorInstanceID:  specialtyBoundaryValue(observation.Boundary.CollectorInstanceID),
		HostedZoneID:         hostedZoneID,
		HostedZoneName:       specialtyStringPtr(strings.TrimSpace(observation.HostedZoneName)),
		HostedZonePrivate:    specialtyBoolPtr(observation.HostedZonePrivate),
		RecordName:           recordName,
		NormalizedRecordName: normalizedRecordName,
		RecordType:           recordType,
		SetIdentifier:        specialtyStringPtr(setIdentifier),
		TTL:                  observation.TTL,
		Values:               cloneDNSStrings(observation.Values),
		AliasTarget:          dnsAliasTargetPayload(observation.AliasTarget),
		RoutingPolicy:        dnsRoutingPolicyPayload(observation.RoutingPolicy),
		CorrelationAnchors:   dnsRecordAnchors(recordName, observation.Values, observation.AliasTarget),
		HasAliasTarget:       specialtyBoolPtr(observation.AliasTarget != nil),
		SourceHostedZoneName: specialtyStringPtr(strings.TrimSpace(observation.HostedZoneName)),
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws_dns_record payload: %w", err)
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = dnsRecordSourceID(hostedZoneID, recordName, recordType, setIdentifier)
	}
	return specialtyFact(AWSKindDNSRecord, stableKey, observation.Boundary, observation.SourceURI, recordID, payload)
}

func normalizeDNSName(input string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(input)), ".")
}

func dnsAliasTargetPayload(input *DNSAliasTarget) *awsv1.DNSAliasTarget {
	if input == nil {
		return nil
	}
	dnsName := strings.TrimSpace(input.DNSName)
	return &awsv1.DNSAliasTarget{
		DNSName:               dnsName,
		NormalizedDNSName:     normalizeDNSName(dnsName),
		HostedZoneID:          strings.TrimSpace(input.HostedZoneID),
		EvaluateTargetHealth:  input.EvaluateTargetHealth,
		TargetIdentityFamily:  "dns_name",
		TargetIdentityVersion: "1.0.0",
	}
}

func dnsRoutingPolicyPayload(input DNSRoutingPolicy) *awsv1.DNSRoutingPolicy {
	output := awsv1.DNSRoutingPolicy{
		Weight:                  input.Weight,
		Region:                  specialtyStringPtr(strings.TrimSpace(input.Region)),
		Failover:                specialtyStringPtr(strings.TrimSpace(input.Failover)),
		HealthCheckID:           specialtyStringPtr(strings.TrimSpace(input.HealthCheckID)),
		MultiValueAnswer:        input.MultiValueAnswer,
		TrafficPolicyInstanceID: specialtyStringPtr(strings.TrimSpace(input.TrafficPolicyInstanceID)),
		CIDRCollectionID:        specialtyStringPtr(strings.TrimSpace(input.CIDRCollectionID)),
		CIDRLocationName:        specialtyStringPtr(strings.TrimSpace(input.CIDRLocationName)),
	}
	geo := awsv1.DNSGeoLocation{
		ContinentCode:   specialtyStringPtr(strings.TrimSpace(input.GeoLocation.ContinentCode)),
		CountryCode:     specialtyStringPtr(strings.TrimSpace(input.GeoLocation.CountryCode)),
		SubdivisionCode: specialtyStringPtr(strings.TrimSpace(input.GeoLocation.SubdivisionCode)),
	}
	if dnsHasAnyStringValue(*geo.ContinentCode, *geo.CountryCode, *geo.SubdivisionCode) {
		output.GeoLocation = &geo
	}
	if input.Weight == nil &&
		!dnsHasAnyStringValue(*output.Region, *output.Failover, *output.HealthCheckID, *output.TrafficPolicyInstanceID, *output.CIDRCollectionID, *output.CIDRLocationName) &&
		input.MultiValueAnswer == nil && output.GeoLocation == nil {
		return nil
	}
	return &output
}

func dnsHasAnyStringValue(values ...string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}

func dnsRecordAnchors(recordName string, values []string, aliasTarget *DNSAliasTarget) []string {
	anchors := []string{recordName, normalizeDNSName(recordName)}
	anchors = append(anchors, values...)
	if aliasTarget != nil {
		anchors = append(anchors, aliasTarget.DNSName, normalizeDNSName(aliasTarget.DNSName))
	}
	return specialtyAnchors(nil, anchors...)
}

func dnsRecordSourceID(hostedZoneID, recordName, recordType, setIdentifier string) string {
	parts := []string{hostedZoneID, recordType, normalizeDNSName(recordName)}
	if setIdentifier != "" {
		parts = append(parts, setIdentifier)
	}
	return strings.Join(parts, "#")
}

func cloneDNSStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	output := make([]string, len(input))
	copy(output, input)
	return output
}
