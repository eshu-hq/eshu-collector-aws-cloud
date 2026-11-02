// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// cloudFrontDistributionRecord gives a ListDistributions summary its typed
// home and the KMS-free attribute set the in-tree distributionObservation
// emits. Tags stay nil because the listing makes no ListTagsForResource
// call. Custom header values stay out (they can carry secrets); only the
// header names are recorded, matching the in-tree Origin view.
func cloudFrontDistributionRecord(distribution cloudfronttypes.DistributionSummary, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(distribution.ARN))
	id := strings.TrimSpace(aws.ToString(distribution.Id))
	row := record(arn, catalog.ServiceCloudFront, region, netdataFirstNonEmpty(aws.ToString(distribution.DomainName), id, arn), "distribution")
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceCloudFront,
		ResourceType: catalog.ResourceTypeCloudFrontDistribution,
		ResourceID:   netdataFirstNonEmpty(arn, id),
		Name:         strings.TrimSpace(aws.ToString(distribution.DomainName)),
		ARN:          arn,
		State:        strings.TrimSpace(aws.ToString(distribution.Status)),
		Attributes: map[string]any{
			"id":                 id,
			"domain_name":        strings.TrimSpace(aws.ToString(distribution.DomainName)),
			"status":             strings.TrimSpace(aws.ToString(distribution.Status)),
			"enabled":            aws.ToBool(distribution.Enabled),
			"comment":            strings.TrimSpace(aws.ToString(distribution.Comment)),
			"http_version":       strings.TrimSpace(string(distribution.HttpVersion)),
			"ipv6_enabled":       aws.ToBool(distribution.IsIPV6Enabled),
			"last_modified_time": cloudFrontTimeOrNil(distribution.LastModifiedTime),
			"price_class":        strings.TrimSpace(string(distribution.PriceClass)),
			"staging":            aws.ToBool(distribution.Staging),
			"aliases":            cloudFrontStrings(distribution.Aliases),
			"web_acl_id":         strings.TrimSpace(aws.ToString(distribution.WebACLId)),
			"origins":            cloudFrontOriginAttributes(distribution.Origins),
		},
		CorrelationAnchors: []string{arn, id, aws.ToString(distribution.DomainName)},
		SourceRecordID:     netdataFirstNonEmpty(arn, id),
	}
	if attributes := cloudFrontCacheBehaviorAttributes(distribution.DefaultCacheBehavior); attributes != nil {
		resource.Attributes["default_cache_behavior"] = attributes
	}
	if attributes := cloudFrontCacheBehaviorsAttributes(distribution.CacheBehaviors); attributes != nil {
		resource.Attributes["cache_behaviors"] = attributes
	}
	if attributes := cloudFrontViewerCertificateAttributes(distribution.ViewerCertificate); attributes != nil {
		resource.Attributes["viewer_certificate"] = attributes
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

func cloudFrontOriginAttributes(origins *cloudfronttypes.Origins) []map[string]any {
	if origins == nil || len(origins.Items) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(origins.Items))
	for _, origin := range origins.Items {
		output = append(output, map[string]any{
			"id":                       strings.TrimSpace(aws.ToString(origin.Id)),
			"domain_name":              strings.TrimSpace(aws.ToString(origin.DomainName)),
			"origin_path":              strings.TrimSpace(aws.ToString(origin.OriginPath)),
			"origin_access_control_id": strings.TrimSpace(aws.ToString(origin.OriginAccessControlId)),
			"custom_header_names":      cloudFrontCustomHeaderNames(origin.CustomHeaders),
		})
	}
	return output
}

func cloudFrontCustomHeaderNames(headers *cloudfronttypes.CustomHeaders) []string {
	if headers == nil || len(headers.Items) == 0 {
		return nil
	}
	output := make([]string, 0, len(headers.Items))
	for _, header := range headers.Items {
		if name := strings.TrimSpace(aws.ToString(header.HeaderName)); name != "" {
			output = append(output, name)
		}
	}
	return output
}

func cloudFrontCacheBehaviorsAttributes(behaviors *cloudfronttypes.CacheBehaviors) []map[string]any {
	if behaviors == nil || len(behaviors.Items) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(behaviors.Items))
	for _, behavior := range behaviors.Items {
		behavior := behavior
		if attributes := cloudFrontPathCacheBehaviorAttributes(&behavior); attributes != nil {
			output = append(output, attributes)
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func cloudFrontCacheBehaviorAttributes(behavior *cloudfronttypes.DefaultCacheBehavior) map[string]any {
	if behavior == nil || !cloudFrontHasDefaultCacheBehaviorData(behavior) {
		return nil
	}
	return cloudFrontCacheBehaviorFields(
		aws.ToString(behavior.TargetOriginId),
		string(behavior.ViewerProtocolPolicy),
		cloudFrontAllowedMethods(behavior.AllowedMethods),
		cloudFrontCachedMethods(behavior.AllowedMethods),
		aws.ToString(behavior.CachePolicyId),
		aws.ToString(behavior.OriginRequestPolicyId),
		aws.ToString(behavior.ResponseHeadersPolicyId),
		behavior.Compress,
		"", false)
}

func cloudFrontPathCacheBehaviorAttributes(behavior *cloudfronttypes.CacheBehavior) map[string]any {
	if behavior == nil || !cloudFrontHasPathCacheBehaviorData(behavior) {
		return nil
	}
	return cloudFrontCacheBehaviorFields(
		aws.ToString(behavior.TargetOriginId),
		string(behavior.ViewerProtocolPolicy),
		cloudFrontAllowedMethods(behavior.AllowedMethods),
		cloudFrontCachedMethods(behavior.AllowedMethods),
		aws.ToString(behavior.CachePolicyId),
		aws.ToString(behavior.OriginRequestPolicyId),
		aws.ToString(behavior.ResponseHeadersPolicyId),
		behavior.Compress,
		aws.ToString(behavior.PathPattern), true)
}

func cloudFrontCacheBehaviorFields(
	targetOriginID, viewerProtocolPolicy string,
	allowedMethods, cachedMethods []string,
	cachePolicyID, originRequestPolicyID, responseHeadersPolicyID string,
	compress *bool, pathPattern string, includePathPattern bool,
) map[string]any {
	attributes := map[string]any{}
	if value := strings.TrimSpace(targetOriginID); value != "" {
		attributes["target_origin_id"] = value
	}
	if value := strings.TrimSpace(viewerProtocolPolicy); value != "" {
		attributes["viewer_protocol_policy"] = value
	}
	if allowedMethods != nil {
		attributes["allowed_methods"] = allowedMethods
	}
	if cachedMethods != nil {
		attributes["cached_methods"] = cachedMethods
	}
	if value := strings.TrimSpace(cachePolicyID); value != "" {
		attributes["cache_policy_id"] = value
	}
	if value := strings.TrimSpace(originRequestPolicyID); value != "" {
		attributes["origin_request_policy_id"] = value
	}
	if value := strings.TrimSpace(responseHeadersPolicyID); value != "" {
		attributes["response_headers_policy_id"] = value
	}
	if compress != nil {
		attributes["compress"] = *compress
	}
	if includePathPattern {
		if value := strings.TrimSpace(pathPattern); value != "" {
			attributes["path_pattern"] = value
		}
	}
	return attributes
}

func cloudFrontHasDefaultCacheBehaviorData(behavior *cloudfronttypes.DefaultCacheBehavior) bool {
	if behavior == nil {
		return false
	}
	return strings.TrimSpace(aws.ToString(behavior.TargetOriginId)) != "" ||
		strings.TrimSpace(string(behavior.ViewerProtocolPolicy)) != "" ||
		len(cloudFrontAllowedMethods(behavior.AllowedMethods)) > 0 ||
		len(cloudFrontCachedMethods(behavior.AllowedMethods)) > 0 ||
		strings.TrimSpace(aws.ToString(behavior.CachePolicyId)) != "" ||
		strings.TrimSpace(aws.ToString(behavior.OriginRequestPolicyId)) != "" ||
		strings.TrimSpace(aws.ToString(behavior.ResponseHeadersPolicyId)) != "" ||
		behavior.Compress != nil
}

func cloudFrontHasPathCacheBehaviorData(behavior *cloudfronttypes.CacheBehavior) bool {
	if behavior == nil {
		return false
	}
	if strings.TrimSpace(aws.ToString(behavior.PathPattern)) != "" {
		return true
	}
	return strings.TrimSpace(aws.ToString(behavior.TargetOriginId)) != "" ||
		strings.TrimSpace(string(behavior.ViewerProtocolPolicy)) != "" ||
		len(cloudFrontAllowedMethods(behavior.AllowedMethods)) > 0 ||
		len(cloudFrontCachedMethods(behavior.AllowedMethods)) > 0 ||
		strings.TrimSpace(aws.ToString(behavior.CachePolicyId)) != "" ||
		strings.TrimSpace(aws.ToString(behavior.OriginRequestPolicyId)) != "" ||
		strings.TrimSpace(aws.ToString(behavior.ResponseHeadersPolicyId)) != "" ||
		behavior.Compress != nil
}

func cloudFrontAllowedMethods(methods *cloudfronttypes.AllowedMethods) []string {
	if methods == nil || methods.Quantity == nil || aws.ToInt32(methods.Quantity) == 0 {
		return nil
	}
	return cloudFrontMethodNames(methods.Items)
}

func cloudFrontCachedMethods(methods *cloudfronttypes.AllowedMethods) []string {
	if methods == nil || methods.CachedMethods == nil || len(methods.CachedMethods.Items) == 0 {
		return nil
	}
	return cloudFrontMethodNames(methods.CachedMethods.Items)
}

func cloudFrontMethodNames(methods []cloudfronttypes.Method) []string {
	if len(methods) == 0 {
		return nil
	}
	output := make([]string, 0, len(methods))
	for _, method := range methods {
		output = append(output, string(method))
	}
	return output
}

func cloudFrontViewerCertificateAttributes(certificate *cloudfronttypes.ViewerCertificate) map[string]any {
	if certificate == nil || !cloudFrontHasViewerCertificateData(certificate) {
		return nil
	}
	attributes := map[string]any{}
	if value := strings.TrimSpace(aws.ToString(certificate.ACMCertificateArn)); value != "" {
		attributes["acm_certificate_arn"] = value
	}
	if certificate.CloudFrontDefaultCertificate != nil {
		attributes["cloudfront_default_certificate"] = *certificate.CloudFrontDefaultCertificate
	}
	if value := strings.TrimSpace(aws.ToString(certificate.IAMCertificateId)); value != "" {
		attributes["iam_certificate_id"] = value
	}
	if value := strings.TrimSpace(string(certificate.MinimumProtocolVersion)); value != "" {
		attributes["minimum_protocol_version"] = value
	}
	if value := strings.TrimSpace(string(certificate.SSLSupportMethod)); value != "" {
		attributes["ssl_support_method"] = value
	}
	return attributes
}

func cloudFrontHasViewerCertificateData(certificate *cloudfronttypes.ViewerCertificate) bool {
	if certificate == nil {
		return false
	}
	return strings.TrimSpace(aws.ToString(certificate.ACMCertificateArn)) != "" ||
		certificate.CloudFrontDefaultCertificate != nil ||
		strings.TrimSpace(aws.ToString(certificate.IAMCertificateId)) != "" ||
		strings.TrimSpace(string(certificate.MinimumProtocolVersion)) != "" ||
		strings.TrimSpace(string(certificate.SSLSupportMethod)) != ""
}

func cloudFrontTimeOrNil(input *time.Time) any {
	if input == nil {
		return nil
	}
	return input.UTC()
}

func cloudFrontStrings(aliases *cloudfronttypes.Aliases) []string {
	if aliases == nil || len(aliases.Items) == 0 {
		return nil
	}
	return append([]string(nil), aliases.Items...)
}
