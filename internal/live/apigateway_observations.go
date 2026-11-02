// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsapigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	awsapigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// The API Gateway resource and relationship types reuse the satellite catalog
// constants (pinned to the in-tree catalog strings by
// catalog/api_test.go); the parity note in the lane report locks each value
// against the in-tree oracle key.
const (
	apigatewayRestAPIResourceType    = catalog.ResourceTypeAPIGatewayRESTAPI
	apigatewayV2APIResourceType      = catalog.ResourceTypeAPIGatewayV2API
	apigatewayDomainNameResourceType = catalog.ResourceTypeAPIGatewayDomainName

	apigatewayUsesACMCertificateRelationship = catalog.RelationshipAPIGatewayDomainUsesACMCertificate
)

// apigatewayRestAPIRecord gives a GetRestApis row its typed home. The
// translation mirrors the in-tree restAPIObservation field for field,
// including tags: GetRestApis returns them inline, so no extra read is
// needed. The in-tree stage and integration relationships need reads the
// listing does not make, so the row carries none.
func apigatewayRestAPIRecord(api awsapigatewaytypes.RestApi, region string) collector.Record {
	apiID := strings.TrimSpace(aws.ToString(api.Id))
	name := apigatewayFirstNonEmpty(aws.ToString(api.Name), apiID)
	row := record(apiID, catalog.ServiceAPIGateway, region, name, "rest-api")
	endpointTypes, vpcEndpointIDs := apigatewayEndpointConfiguration(api.EndpointConfiguration)
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceAPIGateway,
		ResourceType: apigatewayRestAPIResourceType,
		ResourceID:   apiID,
		Name:         name,
		ARN:          apigatewayRestAPIARN(region, apiID),
		State:        strings.TrimSpace(string(api.ApiStatus)),
		Tags:         apigatewayCloneStringMap(api.Tags),
		Attributes: map[string]any{
			"api_id":                       apiID,
			"api_kind":                     "rest",
			"description":                  strings.TrimSpace(aws.ToString(api.Description)),
			"created_date":                 apigatewayTimeOrNil(api.CreatedDate),
			"version":                      strings.TrimSpace(aws.ToString(api.Version)),
			"api_status":                   strings.TrimSpace(string(api.ApiStatus)),
			"api_key_source":               strings.TrimSpace(string(api.ApiKeySource)),
			"disable_execute_api_endpoint": api.DisableExecuteApiEndpoint,
			"endpoint_types":               endpointTypes,
			"vpc_endpoint_ids":             vpcEndpointIDs,
		},
		CorrelationAnchors: []string{apiID, strings.TrimSpace(aws.ToString(api.Name))},
		SourceRecordID:     apiID,
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

// apigatewayV2APIRecord gives a GetApis (v2 HTTP/WebSocket) row its typed
// home. The translation mirrors the in-tree v2APIObservation field for
// field, including tags: GetApis returns them inline. The in-tree stage,
// route, integration, and authorizer relationships need reads the listing
// does not make, so the row carries none.
func apigatewayV2APIRecord(api awsapigatewayv2types.Api, region string) collector.Record {
	apiID := strings.TrimSpace(aws.ToString(api.ApiId))
	name := apigatewayFirstNonEmpty(aws.ToString(api.Name), apiID)
	row := record(apiID, catalog.ServiceAPIGateway, region, name, "http-api")
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceAPIGateway,
		ResourceType: apigatewayV2APIResourceType,
		ResourceID:   apiID,
		Name:         name,
		ARN:          apigatewayV2APIARN(region, apiID),
		State:        strings.TrimSpace(string(api.ProtocolType)),
		Tags:         apigatewayCloneStringMap(api.Tags),
		Attributes: map[string]any{
			"api_id":                       apiID,
			"api_kind":                     "v2",
			"protocol_type":                strings.TrimSpace(string(api.ProtocolType)),
			"endpoint":                     strings.TrimSpace(aws.ToString(api.ApiEndpoint)),
			"created_date":                 apigatewayTimeOrNil(api.CreatedDate),
			"description":                  strings.TrimSpace(aws.ToString(api.Description)),
			"disable_execute_api_endpoint": aws.ToBool(api.DisableExecuteApiEndpoint),
			"api_gateway_managed":          apigatewayBoolOrNil(api.ApiGatewayManaged),
			"ip_address_type":              strings.TrimSpace(string(api.IpAddressType)),
		},
		CorrelationAnchors: []string{apiID, strings.TrimSpace(aws.ToString(api.Name)), strings.TrimSpace(aws.ToString(api.ApiEndpoint))},
		SourceRecordID:     apiID,
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

// apigatewayRestDomainNameRecord gives a GetDomainNames (v1) row its typed
// home. The translation mirrors the in-tree domainObservation for a REST
// domain field for field, including tags and the ACM certificate edges: the
// certificate ARNs arrive inline, so no extra read is needed. Base-path
// mappings need a GetBasePathMappings read the listing does not make, so
// the mappings attribute stays nil and no maps-to-API edge is emitted.
func apigatewayRestDomainNameRecord(domain awsapigatewaytypes.DomainName, region string) collector.Record {
	name := strings.TrimSpace(aws.ToString(domain.DomainName))
	arn := strings.TrimSpace(aws.ToString(domain.DomainNameArn))
	resourceID := apigatewayFirstNonEmpty(name, arn)
	row := record("", catalog.ServiceAPIGateway, region, name, "domain-name")
	endpointTypes, _ := apigatewayEndpointConfiguration(domain.EndpointConfiguration)
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceAPIGateway,
		ResourceType: apigatewayDomainNameResourceType,
		ResourceID:   resourceID,
		Name:         apigatewayFirstNonEmpty(name, resourceID),
		ARN:          arn,
		State:        strings.TrimSpace(string(domain.DomainNameStatus)),
		Tags:         apigatewayCloneStringMap(domain.Tags),
		Attributes: map[string]any{
			"api_kind":                    "rest",
			"domain_name":                 name,
			"status":                      strings.TrimSpace(string(domain.DomainNameStatus)),
			"endpoint_types":              endpointTypes,
			"regional_domain_name":        strings.TrimSpace(aws.ToString(domain.RegionalDomainName)),
			"regional_hosted_zone_id":     strings.TrimSpace(aws.ToString(domain.RegionalHostedZoneId)),
			"distribution_domain_name":    strings.TrimSpace(aws.ToString(domain.DistributionDomainName)),
			"distribution_hosted_zone_id": strings.TrimSpace(aws.ToString(domain.DistributionHostedZoneId)),
			"certificate_arns": apigatewayCloneStrings([]string{
				aws.ToString(domain.CertificateArn),
				aws.ToString(domain.RegionalCertificateArn),
				aws.ToString(domain.OwnershipVerificationCertificateArn),
			}),
			"security_policy":       strings.TrimSpace(string(domain.SecurityPolicy)),
			"api_mapping_selection": "",
			"mappings":              nil,
		},
		CorrelationAnchors: []string{name, arn},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	row.Relationships = append(row.Relationships, apigatewayDomainCertificateEdges(
		region, resourceID, arn, "rest", name,
		[]string{
			aws.ToString(domain.CertificateArn),
			aws.ToString(domain.RegionalCertificateArn),
			aws.ToString(domain.OwnershipVerificationCertificateArn),
		})...)
	return row
}

// apigatewayV2DomainNameRecord gives a GetDomainNames (v2) row its typed
// home. The translation mirrors the in-tree domainObservation for a v2
// domain field for field, including tags and the ACM certificate edges from
// the domain-name configurations. API mappings need a GetApiMappings read
// the listing does not make, so the mappings attribute stays nil and no
// maps-to-API edge is emitted.
func apigatewayV2DomainNameRecord(domain awsapigatewayv2types.DomainName, region string) collector.Record {
	name := strings.TrimSpace(aws.ToString(domain.DomainName))
	arn := strings.TrimSpace(aws.ToString(domain.DomainNameArn))
	resourceID := apigatewayFirstNonEmpty(name, arn)
	row := record(arn, catalog.ServiceAPIGateway, region, name, "domain-name")
	configs := domain.DomainNameConfigurations
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceAPIGateway,
		ResourceType: apigatewayDomainNameResourceType,
		ResourceID:   resourceID,
		Name:         apigatewayFirstNonEmpty(name, resourceID),
		ARN:          arn,
		State:        apigatewayFirstV2DomainStatus(configs),
		Tags:         apigatewayCloneStringMap(domain.Tags),
		Attributes: map[string]any{
			"api_kind":                "v2",
			"domain_name":             name,
			"status":                  apigatewayFirstV2DomainStatus(configs),
			"endpoint_types":          apigatewayV2DomainEndpointTypes(configs),
			"regional_domain_name":    apigatewayFirstV2APIGatewayDomainName(configs),
			"regional_hosted_zone_id": apigatewayFirstV2HostedZoneID(configs),
			"certificate_arns":        apigatewayV2DomainCertificateARNs(configs),
			"security_policy":         apigatewayFirstV2SecurityPolicy(configs),
			"api_mapping_selection":   strings.TrimSpace(aws.ToString(domain.ApiMappingSelectionExpression)),
			"mappings":                nil,
		},
		CorrelationAnchors: []string{name, arn},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	var certificateARNs []string
	for _, config := range configs {
		certificateARNs = append(certificateARNs,
			aws.ToString(config.CertificateArn),
			aws.ToString(config.OwnershipVerificationCertificateArn))
	}
	row.Relationships = append(row.Relationships, apigatewayDomainCertificateEdges(
		region, resourceID, arn, "v2", name, certificateARNs)...)
	return row
}

// apigatewayDomainCertificateEdges mirrors the in-tree certificate loop of
// domainRelationships: one uses-ACM-certificate edge per reported
// certificate ARN.
func apigatewayDomainCertificateEdges(region, sourceID, sourceARN, apiKind, domain string, certificateARNs []string) []collector.LiveRelationship {
	if strings.TrimSpace(sourceID) == "" {
		return nil
	}
	var edges []collector.LiveRelationship
	for _, candidate := range apigatewayCloneStrings(certificateARNs) {
		edges = append(edges, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceAPIGateway,
			RelationshipType: apigatewayUsesACMCertificateRelationship,
			SourceResourceID: sourceID, SourceARN: strings.TrimSpace(sourceARN),
			TargetResourceID: candidate, TargetARN: candidate,
			TargetType: "aws_acm_certificate",
			Attributes: map[string]any{
				"api_kind": strings.TrimSpace(apiKind),
				"domain":   strings.TrimSpace(domain),
			},
			SourceRecordID: sourceID + "->" + candidate,
		})
	}
	return edges
}

func apigatewayRestAPIARN(region, apiID string) string {
	if strings.TrimSpace(apiID) == "" {
		return ""
	}
	region = strings.TrimSpace(region)
	return "arn:" + partitionForRegion(region) + ":apigateway:" + region + "::/restapis/" + strings.TrimSpace(apiID)
}

func apigatewayV2APIARN(region, apiID string) string {
	if strings.TrimSpace(apiID) == "" {
		return ""
	}
	region = strings.TrimSpace(region)
	return "arn:" + partitionForRegion(region) + ":apigateway:" + region + "::/apis/" + strings.TrimSpace(apiID)
}

func apigatewayEndpointConfiguration(input *awsapigatewaytypes.EndpointConfiguration) ([]string, []string) {
	if input == nil {
		return nil, nil
	}
	var types []string
	for _, value := range input.Types {
		if trimmed := strings.TrimSpace(string(value)); trimmed != "" {
			types = append(types, trimmed)
		}
	}
	return apigatewayCloneStrings(types), apigatewayCloneStrings(input.VpcEndpointIds)
}

func apigatewayFirstV2DomainStatus(configs []awsapigatewayv2types.DomainNameConfiguration) string {
	for _, config := range configs {
		if value := strings.TrimSpace(string(config.DomainNameStatus)); value != "" {
			return value
		}
	}
	return ""
}

func apigatewayFirstV2APIGatewayDomainName(configs []awsapigatewayv2types.DomainNameConfiguration) string {
	for _, config := range configs {
		if value := strings.TrimSpace(aws.ToString(config.ApiGatewayDomainName)); value != "" {
			return value
		}
	}
	return ""
}

func apigatewayFirstV2HostedZoneID(configs []awsapigatewayv2types.DomainNameConfiguration) string {
	for _, config := range configs {
		if value := strings.TrimSpace(aws.ToString(config.HostedZoneId)); value != "" {
			return value
		}
	}
	return ""
}

func apigatewayFirstV2SecurityPolicy(configs []awsapigatewayv2types.DomainNameConfiguration) string {
	for _, config := range configs {
		if value := strings.TrimSpace(string(config.SecurityPolicy)); value != "" {
			return value
		}
	}
	return ""
}

func apigatewayV2DomainEndpointTypes(configs []awsapigatewayv2types.DomainNameConfiguration) []string {
	var values []string
	for _, config := range configs {
		if value := strings.TrimSpace(string(config.EndpointType)); value != "" {
			values = append(values, value)
		}
	}
	return apigatewayCloneStrings(values)
}

func apigatewayV2DomainCertificateARNs(configs []awsapigatewayv2types.DomainNameConfiguration) []string {
	var values []string
	for _, config := range configs {
		values = append(values, aws.ToString(config.CertificateArn), aws.ToString(config.OwnershipVerificationCertificateArn))
	}
	return apigatewayCloneStrings(values)
}

func apigatewayCloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			output[trimmed] = value
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func apigatewayCloneStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(input))
	var output []string
	for _, value := range input {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		output = append(output, trimmed)
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func apigatewayBoolOrNil(input *bool) any {
	if input == nil {
		return nil
	}
	return *input
}

func apigatewayTimeOrNil(input *time.Time) any {
	if input == nil || input.IsZero() {
		return nil
	}
	return input.UTC()
}

func apigatewayFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
