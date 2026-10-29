// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// cloudFrontDistributionRecord maps only metadata in ListDistributions.
// Custom origin header values and certificate bodies are never observed.
func cloudFrontDistributionRecord(raw cloudfronttypes.DistributionSummary) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(raw.ARN))
	id := strings.TrimSpace(aws.ToString(raw.Id))
	domain := strings.TrimSpace(aws.ToString(raw.DomainName))
	resourceID := cloudFrontFirst(arn, id, domain)
	name := cloudFrontFirst(id, domain, arn)
	if resourceID == "" {
		return collector.Record{}, fmt.Errorf("cloudfront distribution requires arn, id, or domain name")
	}
	row := record(arn, "cloudfront", "aws-global", name, "distribution")
	attrs := map[string]any{
		"id": id, "domain_name": domain, "status": strings.TrimSpace(aws.ToString(raw.Status)),
		"enabled": aws.ToBool(raw.Enabled), "comment": strings.TrimSpace(aws.ToString(raw.Comment)),
		"http_version": string(raw.HttpVersion), "ipv6_enabled": aws.ToBool(raw.IsIPV6Enabled),
		"last_modified_time": cloudFrontTime(raw.LastModifiedTime), "price_class": string(raw.PriceClass),
		"staging": aws.ToBool(raw.Staging), "aliases": cloudFrontAliases(raw.Aliases),
		"web_acl_id": strings.TrimSpace(aws.ToString(raw.WebACLId)), "origins": cloudFrontOrigins(raw.Origins),
	}
	if behavior := cloudFrontDefaultBehavior(raw.DefaultCacheBehavior); behavior != nil {
		attrs["default_cache_behavior"] = behavior
	}
	if behaviors := cloudFrontBehaviors(raw.CacheBehaviors); behaviors != nil {
		attrs["cache_behaviors"] = behaviors
	}
	if certificate := cloudFrontCertificate(raw.ViewerCertificate); certificate != nil {
		attrs["viewer_certificate"] = certificate
	}
	row.Resource = &collector.LiveResource{
		Region: "aws-global", ServiceKind: "cloudfront", ResourceType: "aws_cloudfront_distribution",
		ResourceID: resourceID, ARN: arn, Name: name, State: strings.TrimSpace(aws.ToString(raw.Status)),
		Attributes: attrs, CorrelationAnchors: []string{arn, id, domain}, SourceRecordID: resourceID,
	}
	if raw.ViewerCertificate != nil {
		if certARN := strings.TrimSpace(aws.ToString(raw.ViewerCertificate.ACMCertificateArn)); certARN != "" {
			row.Relationships = append(row.Relationships, collector.LiveRelationship{
				Region: "aws-global", ServiceKind: "cloudfront", RelationshipType: "cloudfront_distribution_uses_acm_certificate",
				SourceResourceID: resourceID, SourceARN: arn, TargetResourceID: certARN, TargetARN: certARN,
				TargetType: "aws_acm_certificate", SourceRecordID: resourceID + "->" + certARN,
				Attributes: map[string]any{"distribution_id": id},
			})
		}
	}
	if webACLID := strings.TrimSpace(aws.ToString(raw.WebACLId)); webACLID != "" {
		webACLARN := ""
		if strings.HasPrefix(webACLID, "arn:") {
			webACLARN = webACLID
		}
		row.Relationships = append(row.Relationships, collector.LiveRelationship{
			Region: "aws-global", ServiceKind: "cloudfront", RelationshipType: "cloudfront_distribution_uses_waf_web_acl",
			SourceResourceID: resourceID, SourceARN: arn, TargetResourceID: webACLID, TargetARN: webACLARN,
			TargetType: "aws_waf_web_acl", SourceRecordID: resourceID + "->" + webACLID,
			Attributes: map[string]any{"distribution_id": id},
		})
	}
	return row, nil
}

func cloudFrontFirst(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func cloudFrontTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}

func cloudFrontAliases(value *cloudfronttypes.Aliases) []string {
	if value == nil {
		return nil
	}
	return cloudFrontStrings(value.Items)
}

func cloudFrontStrings(values []string) []string {
	var output []string
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			output = append(output, value)
		}
	}
	return output
}

func cloudFrontOrigins(value *cloudfronttypes.Origins) []map[string]any {
	if value == nil || len(value.Items) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(value.Items))
	for _, origin := range value.Items {
		var names []string
		if origin.CustomHeaders != nil {
			for _, header := range origin.CustomHeaders.Items {
				if name := strings.TrimSpace(aws.ToString(header.HeaderName)); name != "" {
					names = append(names, name)
				}
			}
		}
		output = append(output, map[string]any{
			"id":                       strings.TrimSpace(aws.ToString(origin.Id)),
			"domain_name":              strings.TrimSpace(aws.ToString(origin.DomainName)),
			"origin_path":              strings.TrimSpace(aws.ToString(origin.OriginPath)),
			"origin_access_control_id": strings.TrimSpace(aws.ToString(origin.OriginAccessControlId)),
			"custom_header_names":      names,
		})
	}
	return output
}

func cloudFrontDefaultBehavior(value *cloudfronttypes.DefaultCacheBehavior) map[string]any {
	if value == nil {
		return nil
	}
	return cloudFrontBehavior("", value.TargetOriginId, value.ViewerProtocolPolicy, value.AllowedMethods,
		value.CachePolicyId, value.OriginRequestPolicyId, value.ResponseHeadersPolicyId, value.Compress)
}

func cloudFrontBehaviors(value *cloudfronttypes.CacheBehaviors) []map[string]any {
	if value == nil {
		return nil
	}
	var output []map[string]any
	for _, item := range value.Items {
		if attrs := cloudFrontBehavior(aws.ToString(item.PathPattern), item.TargetOriginId, item.ViewerProtocolPolicy,
			item.AllowedMethods, item.CachePolicyId, item.OriginRequestPolicyId, item.ResponseHeadersPolicyId, item.Compress); attrs != nil {
			output = append(output, attrs)
		}
	}
	return output
}

func cloudFrontBehavior(path string, target *string, policy cloudfronttypes.ViewerProtocolPolicy,
	methods *cloudfronttypes.AllowedMethods, cache, request, response *string, compress *bool,
) map[string]any {
	attrs := map[string]any{}
	if value := strings.TrimSpace(path); value != "" {
		attrs["path_pattern"] = value
	}
	if value := strings.TrimSpace(aws.ToString(target)); value != "" {
		attrs["target_origin_id"] = value
	}
	if value := strings.TrimSpace(string(policy)); value != "" {
		attrs["viewer_protocol_policy"] = value
	}
	if methods != nil {
		var allowed []string
		for _, method := range methods.Items {
			allowed = append(allowed, string(method))
		}
		if allowed = cloudFrontStrings(allowed); len(allowed) > 0 {
			attrs["allowed_methods"] = allowed
		}
		if methods.CachedMethods != nil {
			var cached []string
			for _, method := range methods.CachedMethods.Items {
				cached = append(cached, string(method))
			}
			if cached = cloudFrontStrings(cached); len(cached) > 0 {
				attrs["cached_methods"] = cached
			}
		}
	}
	if value := strings.TrimSpace(aws.ToString(cache)); value != "" {
		attrs["cache_policy_id"] = value
	}
	if value := strings.TrimSpace(aws.ToString(request)); value != "" {
		attrs["origin_request_policy_id"] = value
	}
	if value := strings.TrimSpace(aws.ToString(response)); value != "" {
		attrs["response_headers_policy_id"] = value
	}
	if compress != nil {
		attrs["compress"] = *compress
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func cloudFrontCertificate(value *cloudfronttypes.ViewerCertificate) map[string]any {
	if value == nil {
		return nil
	}
	attrs := map[string]any{}
	if v := strings.TrimSpace(aws.ToString(value.ACMCertificateArn)); v != "" {
		attrs["acm_certificate_arn"] = v
	}
	if value.CloudFrontDefaultCertificate != nil {
		attrs["cloudfront_default_certificate"] = *value.CloudFrontDefaultCertificate
	}
	if v := strings.TrimSpace(aws.ToString(value.IAMCertificateId)); v != "" {
		attrs["iam_certificate_id"] = v
	}
	if v := strings.TrimSpace(string(value.MinimumProtocolVersion)); v != "" {
		attrs["minimum_protocol_version"] = v
	}
	if v := strings.TrimSpace(string(value.SSLSupportMethod)); v != "" {
		attrs["ssl_support_method"] = v
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}
