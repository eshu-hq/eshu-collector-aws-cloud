// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// supportedDNSRecordSet ports the in-tree route53 scanner's supportedRecord
// filter verbatim (go/internal/collector/awscloud/service/route53/scanner.go):
// alias targets always emit, otherwise only A, AAAA, and CNAME rows carry
// values the aws_dns_record fact models. NS, SOA, MX, TXT, and SRV rows stay
// transitional records only.
func supportedDNSRecordSet(set route53types.ResourceRecordSet) bool {
	if set.AliasTarget != nil {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(string(set.Type))) {
	case "A", "AAAA", "CNAME":
		return true
	default:
		return false
	}
}

// hostedZoneObservation maps one SDK hosted zone onto the typed resource
// observation the aws_resource seam facts out. The translation mirrors the
// in-tree hostedZoneObservation field for field, except tags: ListHostedZones
// carries no tags and the reader makes no extra ListTagsForResource call,
// so Tags stays nil while identity, visibility, and counts match in-tree.
func hostedZoneObservation(zone route53types.HostedZone, region string) collector.LiveResource {
	zoneID := strings.TrimSpace(aws.ToString(zone.Id))
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(aws.ToString(zone.Name))), ".")
	var comment string
	private := false
	if zone.Config != nil {
		comment = strings.TrimSpace(aws.ToString(zone.Config.Comment))
		private = zone.Config.PrivateZone
	}
	visibility := "public"
	if private {
		visibility = "private"
	}
	var count int64
	if zone.ResourceRecordSetCount != nil {
		count = *zone.ResourceRecordSetCount
	}
	var linked map[string]any
	if zone.LinkedService != nil {
		principal := strings.TrimSpace(aws.ToString(zone.LinkedService.ServicePrincipal))
		description := strings.TrimSpace(aws.ToString(zone.LinkedService.Description))
		if principal != "" || description != "" {
			linked = map[string]any{"service_principal": principal, "description": description}
		}
	}
	return collector.LiveResource{
		Region:       region,
		ServiceKind:  "route53",
		ResourceType: "aws_route53_hosted_zone",
		ResourceID:   zoneID,
		Name:         strings.TrimSuffix(strings.TrimSpace(aws.ToString(zone.Name)), "."),
		Attributes: map[string]any{
			"caller_reference":          strings.TrimSpace(aws.ToString(zone.CallerReference)),
			"comment":                   comment,
			"linked_service":            linked,
			"normalized_name":           name,
			"private_zone":              private,
			"record_set_count":          count,
			"route53_hosted_zone_id":    zoneID,
			"source_identity_family":    "route53_hosted_zone",
			"source_identity_version":   "1.0.0",
			"zone_visibility_evidence":  visibility,
			"zone_visibility_is_direct": true,
		},
		CorrelationAnchors: []string{zoneID, aws.ToString(zone.Name), name},
		SourceRecordID:     zoneID,
	}
}

// dnsRecordObservation maps one SDK record set onto the typed observation the
// aws_dns_record seam facts out. The translation mirrors the in-tree
// awssdk.mapper plus recordObservation field for field: names stored as
// reported, blank values dropped, nil geo/CIDR sections staying zero, and the source
// record id left empty so the seam applies its in-tree-mirrored default. It
// adds no AWS API call. A supported row without DNS identity is a read
// failure, not a silent skip.
func dnsRecordObservation(set route53types.ResourceRecordSet, zone route53types.HostedZone, region string) (*collector.DNSRecordObservation, error) {
	zoneID := aws.ToString(zone.Id)
	name := aws.ToString(set.Name)
	recordType := string(set.Type)
	if strings.TrimSpace(zoneID) == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(recordType) == "" {
		return nil, fmt.Errorf("route53 record set is missing DNS identity")
	}
	var values []string
	for _, record := range set.ResourceRecords {
		value := strings.TrimSpace(aws.ToString(record.Value))
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return &collector.DNSRecordObservation{
		Boundary:          collector.Boundary{Region: region, ServiceKind: "route53"},
		HostedZoneID:      zoneID,
		HostedZoneName:    aws.ToString(zone.Name),
		HostedZonePrivate: zone.Config != nil && zone.Config.PrivateZone,
		RecordName:        name,
		RecordType:        recordType,
		SetIdentifier:     aws.ToString(set.SetIdentifier),
		TTL:               set.TTL,
		Values:            values,
		AliasTarget:       dnsAliasTargetObservation(set.AliasTarget),
		RoutingPolicy: collector.DNSRoutingPolicy{
			Weight:                  set.Weight,
			Region:                  string(set.Region),
			Failover:                string(set.Failover),
			HealthCheckID:           aws.ToString(set.HealthCheckId),
			MultiValueAnswer:        set.MultiValueAnswer,
			TrafficPolicyInstanceID: aws.ToString(set.TrafficPolicyInstanceId),
			GeoLocation:             dnsGeoLocationObservation(set.GeoLocation),
			CIDRCollectionID:        dnsCIDRCollectionID(set.CidrRoutingConfig),
			CIDRLocationName:        dnsCIDRLocationName(set.CidrRoutingConfig),
		},
	}, nil
}

// dnsAliasTargetObservation mirrors the in-tree mapAliasTarget: nil stays
// nil, otherwise trimmed names with the target-health flag carried through.
func dnsAliasTargetObservation(input *route53types.AliasTarget) *collector.DNSAliasTarget {
	if input == nil {
		return nil
	}
	return &collector.DNSAliasTarget{
		DNSName:              aws.ToString(input.DNSName),
		HostedZoneID:         aws.ToString(input.HostedZoneId),
		EvaluateTargetHealth: input.EvaluateTargetHealth,
	}
}

// dnsGeoLocationObservation mirrors the in-tree mapGeoLocation: nil stays
// zero, otherwise trimmed continent/country/subdivision codes.
func dnsGeoLocationObservation(input *route53types.GeoLocation) collector.DNSGeoLocation {
	if input == nil {
		return collector.DNSGeoLocation{}
	}
	return collector.DNSGeoLocation{
		ContinentCode:   aws.ToString(input.ContinentCode),
		CountryCode:     aws.ToString(input.CountryCode),
		SubdivisionCode: aws.ToString(input.SubdivisionCode),
	}
}

// dnsCIDRCollectionID mirrors the in-tree mapCIDRRouting collection half:
// nil config maps to the empty string.
func dnsCIDRCollectionID(input *route53types.CidrRoutingConfig) string {
	if input == nil {
		return ""
	}
	return aws.ToString(input.CollectionId)
}

// dnsCIDRLocationName mirrors the in-tree mapCIDRRouting location half.
func dnsCIDRLocationName(input *route53types.CidrRoutingConfig) string {
	if input == nil {
		return ""
	}
	return aws.ToString(input.LocationName)
}
