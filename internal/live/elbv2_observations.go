// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awselbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// The ELBv2 resource and relationship types reuse the satellite catalog
// constants (pinned to the in-tree catalog strings by
// catalog/network_test.go); the parity note in the lane report locks each
// value against the in-tree oracle key.
const (
	elbv2LoadBalancerResourceType = catalog.ResourceTypeELBv2LoadBalancer
	elbv2ListenerResourceType     = catalog.ResourceTypeELBv2Listener
	elbv2RuleResourceType         = catalog.ResourceTypeELBv2Rule
	elbv2TargetGroupResourceType  = catalog.ResourceTypeELBv2TargetGroup

	elbv2HasListenerRelationship         = catalog.RelationshipELBv2LoadBalancerHasListener
	elbv2HasRuleRelationship             = catalog.RelationshipELBv2ListenerHasRule
	elbv2RoutesToTargetGroupRelationship = catalog.RelationshipELBv2ListenerRoutesToTargetGroup
	elbv2AttachedToLBRelationship        = catalog.RelationshipELBv2TargetGroupAttachedToLoadBalancer
)

// elbv2LoadBalancerRecord gives a DescribeLoadBalancers row its typed home.
// The translation mirrors the in-tree loadBalancerObservation field for
// field, except tags: the listing makes no DescribeTags call, so Tags stays
// nil while identity, state, and placement match in-tree. The in-tree
// scanner emits no relationship on the load balancer resource itself.
func elbv2LoadBalancerRecord(balancer awselbv2types.LoadBalancer, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(balancer.LoadBalancerArn))
	name := strings.TrimSpace(aws.ToString(balancer.LoadBalancerName))
	row := record(arn, catalog.ServiceELBv2, region, name, "load-balancer")
	state := ""
	if balancer.State != nil {
		state = strings.TrimSpace(string(balancer.State.Code))
	}
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceELBv2,
		ResourceType: elbv2LoadBalancerResourceType,
		ResourceID:   arn,
		Name:         name,
		ARN:          arn,
		State:        state,
		Attributes: map[string]any{
			"availability_zones":       elbv2AvailabilityZones(balancer.AvailabilityZones),
			"canonical_hosted_zone_id": strings.TrimSpace(aws.ToString(balancer.CanonicalHostedZoneId)),
			"created_at":               elbv2TimeOrNil(balancer.CreatedTime),
			"dns_name":                 strings.TrimSpace(aws.ToString(balancer.DNSName)),
			"ip_address_type":          strings.TrimSpace(string(balancer.IpAddressType)),
			"scheme":                   strings.TrimSpace(string(balancer.Scheme)),
			"security_groups":          elbv2CloneStrings(balancer.SecurityGroups),
			"type":                     strings.TrimSpace(string(balancer.Type)),
			"vpc_id":                   strings.TrimSpace(aws.ToString(balancer.VpcId)),
		},
		CorrelationAnchors: []string{arn, name, strings.TrimSpace(aws.ToString(balancer.DNSName))},
		SourceRecordID:     arn,
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

// elbv2ListenerRecord gives a DescribeListeners row its typed home and the
// load-balancer membership edge the in-tree listenerEnvelopes emits. Default
// actions fan out into grouped routes-to-target-group edges; rule actions
// attach to their rule row. Tags stay nil: the listing makes no
// DescribeTags call.
func elbv2ListenerRecord(listener awselbv2types.Listener, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(listener.ListenerArn))
	loadBalancerARN := strings.TrimSpace(aws.ToString(listener.LoadBalancerArn))
	row := record(arn, catalog.ServiceELBv2, region, lastSegment(arn, "/"), "listener")
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceELBv2,
		ResourceType: elbv2ListenerResourceType,
		ResourceID:   arn,
		Name:         arn,
		ARN:          arn,
		Attributes: map[string]any{
			"alpn_policy":       elbv2CloneStrings(listener.AlpnPolicy),
			"certificates":      elbv2Certificates(listener.Certificates),
			"default_actions":   elbv2ActionMaps(listener.DefaultActions),
			"load_balancer_arn": loadBalancerARN,
			"port":              aws.ToInt32(listener.Port),
			"protocol":          strings.TrimSpace(string(listener.Protocol)),
			"ssl_policy":        strings.TrimSpace(aws.ToString(listener.SslPolicy)),
		},
		CorrelationAnchors: []string{arn, loadBalancerARN},
		SourceRecordID:     arn,
	}
	row.Resource = resource
	row.TypedOnly = true
	if loadBalancerARN != "" && arn != "" {
		row.Relationships = append(row.Relationships, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceELBv2,
			RelationshipType: elbv2HasListenerRelationship,
			SourceResourceID: loadBalancerARN, SourceARN: loadBalancerARN,
			TargetResourceID: arn, TargetARN: arn, TargetType: elbv2ListenerResourceType,
			SourceRecordID: loadBalancerARN + "#listener#" + arn,
		})
	}
	row.Relationships = append(row.Relationships,
		elbv2RouteEdges(region, arn, loadBalancerARN, "default_action", "", "", listener.DefaultActions)...)
	return row
}

// elbv2RuleRecord gives a DescribeRules row its typed home, the listener
// membership edge, and the grouped routes-to-target-group edges for the
// rule actions. The SDK Rule carries no listener ARN, so the caller passes
// the listener ARN of the list request. Tags stay nil: the listing makes no
// DescribeTags call.
func elbv2RuleRecord(listenerARN string, rule awselbv2types.Rule, region string) collector.Record {
	listenerARN = strings.TrimSpace(listenerARN)
	arn := strings.TrimSpace(aws.ToString(rule.RuleArn))
	row := record(arn, catalog.ServiceELBv2, region, lastSegment(arn, "/"), "rule")
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceELBv2,
		ResourceType: elbv2RuleResourceType,
		ResourceID:   arn,
		Name:         arn,
		ARN:          arn,
		Attributes: map[string]any{
			"actions":      elbv2ActionMaps(rule.Actions),
			"conditions":   elbv2ConditionMaps(rule.Conditions),
			"is_default":   aws.ToBool(rule.IsDefault),
			"listener_arn": listenerARN,
			"priority":     strings.TrimSpace(aws.ToString(rule.Priority)),
		},
		CorrelationAnchors: []string{arn, listenerARN},
		SourceRecordID:     arn,
	}
	row.Resource = resource
	row.TypedOnly = true
	if listenerARN != "" && arn != "" {
		row.Relationships = append(row.Relationships, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceELBv2,
			RelationshipType: elbv2HasRuleRelationship,
			SourceResourceID: listenerARN, SourceARN: listenerARN,
			TargetResourceID: arn, TargetARN: arn, TargetType: elbv2RuleResourceType,
			Attributes: map[string]any{
				"is_default": aws.ToBool(rule.IsDefault),
				"priority":   strings.TrimSpace(aws.ToString(rule.Priority)),
			},
			SourceRecordID: listenerARN + "#rule#" + arn,
		})
	}
	row.Relationships = append(row.Relationships,
		elbv2RouteEdges(region, listenerARN, "", "rule_action", arn, strings.TrimSpace(aws.ToString(rule.Priority)), rule.Actions)...)
	return row
}

// elbv2TargetGroupRecord gives a DescribeTargetGroups row its typed home and
// one attached-to-load-balancer edge per reported load balancer ARN,
// mirroring the in-tree targetGroupEnvelopes. Tags stay nil: the listing
// makes no DescribeTags call.
func elbv2TargetGroupRecord(group awselbv2types.TargetGroup, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(group.TargetGroupArn))
	name := strings.TrimSpace(aws.ToString(group.TargetGroupName))
	row := record(arn, catalog.ServiceELBv2, region, name, "target-group")
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceELBv2,
		ResourceType: elbv2TargetGroupResourceType,
		ResourceID:   arn,
		Name:         name,
		ARN:          arn,
		Attributes: map[string]any{
			"health_check":       elbv2HealthCheckMap(group),
			"ip_address_type":    strings.TrimSpace(string(group.IpAddressType)),
			"load_balancer_arns": elbv2CloneStrings(group.LoadBalancerArns),
			"port":               aws.ToInt32(group.Port),
			"protocol":           strings.TrimSpace(string(group.Protocol)),
			"protocol_version":   strings.TrimSpace(aws.ToString(group.ProtocolVersion)),
			"target_type":        strings.TrimSpace(string(group.TargetType)),
			"vpc_id":             strings.TrimSpace(aws.ToString(group.VpcId)),
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     arn,
	}
	row.Resource = resource
	row.TypedOnly = true
	for _, candidate := range group.LoadBalancerArns {
		loadBalancerARN := strings.TrimSpace(candidate)
		if loadBalancerARN == "" || arn == "" {
			continue
		}
		row.Relationships = append(row.Relationships, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceELBv2,
			RelationshipType: elbv2AttachedToLBRelationship,
			SourceResourceID: arn, SourceARN: arn,
			TargetResourceID: loadBalancerARN, TargetARN: loadBalancerARN,
			TargetType:     elbv2LoadBalancerResourceType,
			SourceRecordID: arn + "#load-balancer#" + loadBalancerARN,
		})
	}
	return row
}

// elbv2RouteEdges groups one action list by target group into one
// routes-to-target-group edge per group, mirroring the in-tree
// routeRelationshipBuilder: same relationship type, same route entry keys,
// same source-record suffix.
func elbv2RouteEdges(region, listenerARN, loadBalancerARN, routeSource, ruleARN, rulePriority string, actions []awselbv2types.Action) []collector.LiveRelationship {
	listenerARN = strings.TrimSpace(listenerARN)
	if listenerARN == "" {
		return nil
	}
	routes := make(map[string][]map[string]any)
	var order []string
	for _, action := range actions {
		actionType := strings.TrimSpace(string(action.Type))
		for _, target := range elbv2ActionTargetGroups(action) {
			entry := map[string]any{
				"action_type":      actionType,
				"route_source":     routeSource,
				"rule_arn":         strings.TrimSpace(ruleARN),
				"rule_priority":    strings.TrimSpace(rulePriority),
				"target_weight":    target.Weight,
				"target_group_arn": target.ARN,
			}
			if _, ok := routes[target.ARN]; !ok {
				order = append(order, target.ARN)
			}
			routes[target.ARN] = append(routes[target.ARN], entry)
		}
	}
	var edges []collector.LiveRelationship
	for _, targetARN := range order {
		edges = append(edges, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceELBv2,
			RelationshipType: elbv2RoutesToTargetGroupRelationship,
			SourceResourceID: listenerARN, SourceARN: listenerARN,
			TargetResourceID: targetARN, TargetARN: targetARN,
			TargetType: elbv2TargetGroupResourceType,
			Attributes: map[string]any{
				"load_balancer_arn": strings.TrimSpace(loadBalancerARN),
				"routes":            routes[targetARN],
			},
			SourceRecordID: listenerARN + "#target-group#" + targetARN,
		})
	}
	return edges
}

// elbv2ActionTargetGroups mirrors the in-tree actionTargetGroups: the direct
// target plus each forward-config group, deduplicated by ARN.
func elbv2ActionTargetGroups(action awselbv2types.Action) []elbv2TargetGroupRef {
	var refs []elbv2TargetGroupRef
	seen := make(map[string]struct{})
	if arn := strings.TrimSpace(aws.ToString(action.TargetGroupArn)); arn != "" {
		refs = append(refs, elbv2TargetGroupRef{ARN: arn})
		seen[arn] = struct{}{}
	}
	if action.ForwardConfig != nil {
		for _, group := range action.ForwardConfig.TargetGroups {
			arn := strings.TrimSpace(aws.ToString(group.TargetGroupArn))
			if arn == "" {
				continue
			}
			if _, ok := seen[arn]; ok {
				continue
			}
			seen[arn] = struct{}{}
			refs = append(refs, elbv2TargetGroupRef{ARN: arn, Weight: aws.ToInt32(group.Weight)})
		}
	}
	return refs
}

// elbv2TargetGroupRef is one routing target with its forward weight.
type elbv2TargetGroupRef struct {
	ARN    string
	Weight int32
}

func elbv2AvailabilityZones(zones []awselbv2types.AvailabilityZone) []map[string]string {
	if len(zones) == 0 {
		return nil
	}
	output := make([]map[string]string, 0, len(zones))
	for _, zone := range zones {
		output = append(output, map[string]string{
			"name":      strings.TrimSpace(aws.ToString(zone.ZoneName)),
			"subnet_id": strings.TrimSpace(aws.ToString(zone.SubnetId)),
		})
	}
	return output
}

func elbv2Certificates(certificates []awselbv2types.Certificate) []string {
	if len(certificates) == 0 {
		return nil
	}
	var output []string
	for _, certificate := range certificates {
		if arn := strings.TrimSpace(aws.ToString(certificate.CertificateArn)); arn != "" {
			output = append(output, arn)
		}
	}
	return output
}

func elbv2ActionMaps(actions []awselbv2types.Action) []map[string]any {
	if len(actions) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(actions))
	for _, action := range actions {
		entry := map[string]any{
			"forward_target_groups": elbv2WeightedTargetGroupMaps(action.ForwardConfig),
			"order":                 aws.ToInt32(action.Order),
			"target_group_arn":      strings.TrimSpace(aws.ToString(action.TargetGroupArn)),
			"type":                  strings.TrimSpace(string(action.Type)),
		}
		if action.RedirectConfig != nil {
			redirect := action.RedirectConfig
			entry["redirect"] = map[string]any{
				"host":        strings.TrimSpace(aws.ToString(redirect.Host)),
				"path":        strings.TrimSpace(aws.ToString(redirect.Path)),
				"port":        strings.TrimSpace(aws.ToString(redirect.Port)),
				"protocol":    strings.TrimSpace(aws.ToString(redirect.Protocol)),
				"query":       strings.TrimSpace(aws.ToString(redirect.Query)),
				"status_code": strings.TrimSpace(string(redirect.StatusCode)),
			}
		}
		if action.FixedResponseConfig != nil {
			fixed := action.FixedResponseConfig
			entry["fixed_response"] = map[string]any{
				"content_type": strings.TrimSpace(aws.ToString(fixed.ContentType)),
				"message_body": strings.TrimSpace(aws.ToString(fixed.MessageBody)),
				"status_code":  strings.TrimSpace(aws.ToString(fixed.StatusCode)),
			}
		}
		output = append(output, entry)
	}
	return output
}

func elbv2WeightedTargetGroupMaps(config *awselbv2types.ForwardActionConfig) []map[string]any {
	if config == nil || len(config.TargetGroups) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(config.TargetGroups))
	for _, group := range config.TargetGroups {
		output = append(output, map[string]any{
			"target_group_arn": strings.TrimSpace(aws.ToString(group.TargetGroupArn)),
			"weight":           aws.ToInt32(group.Weight),
		})
	}
	return output
}

func elbv2ConditionMaps(conditions []awselbv2types.RuleCondition) []map[string]any {
	if len(conditions) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(conditions))
	for _, condition := range conditions {
		output = append(output, map[string]any{
			"field":                strings.TrimSpace(aws.ToString(condition.Field)),
			"host_header_values":   elbv2HostHeaderValues(condition),
			"http_header_name":     elbv2HTTPHeaderName(condition),
			"http_header_values":   elbv2HTTPHeaderValues(condition),
			"http_request_methods": elbv2HTTPRequestMethods(condition),
			"path_pattern_values":  elbv2PathPatternValues(condition),
			"query_strings":        elbv2QueryStrings(condition),
			"source_ip_values":     elbv2SourceIPValues(condition),
			"values":               elbv2CloneStrings(condition.Values),
		})
	}
	return output
}

func elbv2HostHeaderValues(condition awselbv2types.RuleCondition) []string {
	if condition.HostHeaderConfig == nil {
		return nil
	}
	return elbv2CloneStrings(condition.HostHeaderConfig.Values)
}

func elbv2HTTPHeaderName(condition awselbv2types.RuleCondition) string {
	if condition.HttpHeaderConfig == nil {
		return ""
	}
	return strings.TrimSpace(aws.ToString(condition.HttpHeaderConfig.HttpHeaderName))
}

func elbv2HTTPHeaderValues(condition awselbv2types.RuleCondition) []string {
	if condition.HttpHeaderConfig == nil {
		return nil
	}
	return elbv2CloneStrings(condition.HttpHeaderConfig.Values)
}

func elbv2HTTPRequestMethods(condition awselbv2types.RuleCondition) []string {
	if condition.HttpRequestMethodConfig == nil {
		return nil
	}
	return elbv2CloneStrings(condition.HttpRequestMethodConfig.Values)
}

func elbv2PathPatternValues(condition awselbv2types.RuleCondition) []string {
	if condition.PathPatternConfig == nil {
		return nil
	}
	return elbv2CloneStrings(condition.PathPatternConfig.Values)
}

func elbv2QueryStrings(condition awselbv2types.RuleCondition) []map[string]string {
	if condition.QueryStringConfig == nil || len(condition.QueryStringConfig.Values) == 0 {
		return nil
	}
	output := make([]map[string]string, 0, len(condition.QueryStringConfig.Values))
	for _, value := range condition.QueryStringConfig.Values {
		output = append(output, map[string]string{
			"key":   strings.TrimSpace(aws.ToString(value.Key)),
			"value": strings.TrimSpace(aws.ToString(value.Value)),
		})
	}
	return output
}

func elbv2SourceIPValues(condition awselbv2types.RuleCondition) []string {
	if condition.SourceIpConfig == nil {
		return nil
	}
	return elbv2CloneStrings(condition.SourceIpConfig.Values)
}

func elbv2HealthCheckMap(group awselbv2types.TargetGroup) map[string]any {
	matcher := ""
	if group.Matcher != nil {
		matcher = elbv2FirstNonEmpty(aws.ToString(group.Matcher.HttpCode), aws.ToString(group.Matcher.GrpcCode))
	}
	return map[string]any{
		"enabled":             aws.ToBool(group.HealthCheckEnabled),
		"healthy_threshold":   aws.ToInt32(group.HealthyThresholdCount),
		"interval_seconds":    aws.ToInt32(group.HealthCheckIntervalSeconds),
		"matcher":             matcher,
		"path":                strings.TrimSpace(aws.ToString(group.HealthCheckPath)),
		"port":                strings.TrimSpace(aws.ToString(group.HealthCheckPort)),
		"protocol":            strings.TrimSpace(string(group.HealthCheckProtocol)),
		"timeout_seconds":     aws.ToInt32(group.HealthCheckTimeoutSeconds),
		"unhealthy_threshold": aws.ToInt32(group.UnhealthyThresholdCount),
	}
}

func elbv2CloneStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	output := make([]string, len(input))
	copy(output, input)
	return output
}

func elbv2FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func elbv2TimeOrNil(input *time.Time) any {
	if input == nil || input.IsZero() {
		return nil
	}
	return input.UTC()
}
