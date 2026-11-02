// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsapigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	awsapigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	awselbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func TestHomeElbv2LoadBalancer(t *testing.T) {
	balancer := awselbv2types.LoadBalancer{
		LoadBalancerArn:  aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123"),
		LoadBalancerName: aws.String("web"),
		DNSName:          aws.String("web-abc123.us-east-1.elb.amazonaws.com"),
		Scheme:           awselbv2types.LoadBalancerSchemeEnumInternetFacing,
		Type:             awselbv2types.LoadBalancerTypeEnumApplication,
		State:            &awselbv2types.LoadBalancerState{Code: awselbv2types.LoadBalancerStateEnumActive},
		VpcId:            aws.String("vpc-123"),
		SecurityGroups:   []string{"sg-123"},
		AvailabilityZones: []awselbv2types.AvailabilityZone{
			{ZoneName: aws.String("us-east-1a"), SubnetId: aws.String("subnet-123")},
		},
	}
	got := elbv2LoadBalancerRecord(balancer, "us-east-1")
	if got.Resource == nil {
		t.Fatal("load balancer typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceType != "aws_elbv2_load_balancer" {
		t.Fatalf("load balancer resource type = %q", resource.ResourceType)
	}
	if resource.ResourceID != "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123" ||
		resource.Name != "web" || resource.State != "active" {
		t.Fatalf("load balancer identity = %+v", resource)
	}
	if resource.Attributes["dns_name"] != "web-abc123.us-east-1.elb.amazonaws.com" ||
		resource.Attributes["vpc_id"] != "vpc-123" {
		t.Fatalf("load balancer attributes = %#v", resource.Attributes)
	}
	if len(got.Relationships) != 0 {
		t.Fatalf("load balancer relationships = %#v (in-tree emits none on the LB resource)", got.Relationships)
	}
}

func TestHomeElbv2Listener(t *testing.T) {
	listener := awselbv2types.Listener{
		ListenerArn:     aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/web/abc123/def456"),
		LoadBalancerArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123"),
		Protocol:        awselbv2types.ProtocolEnumHttps,
		Port:            aws.Int32(443),
		SslPolicy:       aws.String("ELBSecurityPolicy-2016-08"),
	}
	got := elbv2ListenerRecord(listener, "us-east-1")
	if got.Resource == nil {
		t.Fatal("listener typed resource missing")
	}
	if got.Resource.ResourceType != "aws_elbv2_listener" {
		t.Fatalf("listener resource type = %q", got.Resource.ResourceType)
	}
	found := false
	for _, edge := range got.Relationships {
		if edge.RelationshipType == "elbv2_load_balancer_has_listener" &&
			edge.SourceResourceID == "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123" &&
			edge.TargetResourceID == "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/web/abc123/def456" {
			found = true
		}
	}
	if !found {
		t.Fatalf("listener has-listener edge missing = %#v", got.Relationships)
	}
}

func TestHomeElbv2Rule(t *testing.T) {
	listenerARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/web/abc123/def456"
	rule := awselbv2types.Rule{
		RuleArn:   aws.String(listenerARN + "/rule/789"),
		Priority:  aws.String("10"),
		IsDefault: aws.Bool(false),
		Actions: []awselbv2types.Action{{
			Type:           awselbv2types.ActionTypeEnumForward,
			TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web-tg/aaa111"),
		}},
	}
	got := elbv2RuleRecord(listenerARN, rule, "us-east-1")
	if got.Resource == nil {
		t.Fatal("rule typed resource missing")
	}
	if got.Resource.ResourceType != "aws_elbv2_rule" {
		t.Fatalf("rule resource type = %q", got.Resource.ResourceType)
	}
	var hasRule, routesTo bool
	for _, edge := range got.Relationships {
		switch edge.RelationshipType {
		case "elbv2_listener_has_rule":
			if edge.SourceResourceID == listenerARN {
				hasRule = true
			}
		case "elbv2_listener_routes_to_target_group":
			if edge.TargetResourceID == "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web-tg/aaa111" {
				routesTo = true
			}
		}
	}
	if !hasRule {
		t.Fatalf("rule has-rule edge missing = %#v", got.Relationships)
	}
	if !routesTo {
		t.Fatalf("rule routes-to-target-group edge missing = %#v", got.Relationships)
	}
}

func TestHomeElbv2TargetGroup(t *testing.T) {
	group := awselbv2types.TargetGroup{
		TargetGroupArn:   aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web-tg/aaa111"),
		TargetGroupName:  aws.String("web-tg"),
		Protocol:         awselbv2types.ProtocolEnumHttp,
		Port:             aws.Int32(80),
		VpcId:            aws.String("vpc-123"),
		LoadBalancerArns: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123"},
	}
	got := elbv2TargetGroupRecord(group, "us-east-1")
	if got.Resource == nil {
		t.Fatal("target group typed resource missing")
	}
	if got.Resource.ResourceType != "aws_elbv2_target_group" {
		t.Fatalf("target group resource type = %q", got.Resource.ResourceType)
	}
	found := false
	for _, edge := range got.Relationships {
		if edge.RelationshipType == "elbv2_target_group_attached_to_load_balancer" &&
			edge.TargetResourceID == "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("target group attached-to-LB edge missing = %#v", got.Relationships)
	}
}

func TestHomeApigatewayRestAPI(t *testing.T) {
	api := awsapigatewaytypes.RestApi{
		Id:          aws.String("a1b2c3"),
		Name:        aws.String("orders"),
		Description: aws.String("orders api"),
		Version:     aws.String("v1"),
		Tags:        map[string]string{"team": "checkout"},
		EndpointConfiguration: &awsapigatewaytypes.EndpointConfiguration{
			Types: []awsapigatewaytypes.EndpointType{"REGIONAL"},
		},
	}
	got := apigatewayRestAPIRecord(api, "us-east-1")
	if got.Resource == nil {
		t.Fatal("REST API typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceType != "aws_apigateway_rest_api" {
		t.Fatalf("REST API resource type = %q", resource.ResourceType)
	}
	if resource.ResourceID != "a1b2c3" || resource.Name != "orders" {
		t.Fatalf("REST API identity = %+v", resource)
	}
	if resource.Attributes["api_kind"] != "rest" || resource.Attributes["version"] != "v1" {
		t.Fatalf("REST API attributes = %#v", resource.Attributes)
	}
	if resource.Tags["team"] != "checkout" {
		t.Fatalf("REST API tags = %#v", resource.Tags)
	}
}

// TestHomeApigatewayRestAPIEnvelopeAdmits is the production regression for
// eshu-hq/eshu#8852: a rest API carrying an API key source must envelope
// into an admissible aws_resource fact. api_key_source trips the SDK
// share-safe guard's api_key substring, failing every claim that carries a
// rest API (same class as the CWL bearer_token_authentication_enabled abort).
func TestHomeApigatewayRestAPIEnvelopeAdmits(t *testing.T) {
	api := awsapigatewaytypes.RestApi{
		Id:           aws.String("a1b2c3"),
		Name:         aws.String("orders"),
		ApiKeySource: "HEADER",
	}
	got := apigatewayRestAPIRecord(api, "us-east-1")
	if got.Resource == nil {
		t.Fatal("REST API typed resource missing")
	}
	observation := collector.ResourceObservation{
		Boundary: wave1Boundary("123456789012", "us-east-1", got.Resource.ServiceKind),
		ARN:      got.Resource.ARN, ResourceID: got.Resource.ResourceID,
		ResourceType: got.Resource.ResourceType, Name: got.Resource.Name,
		State: got.Resource.State, Tags: got.Resource.Tags,
		Attributes:         got.Resource.Attributes,
		CorrelationAnchors: append([]string(nil), got.Resource.CorrelationAnchors...),
		SourceRecordID:     got.Resource.SourceRecordID,
		SourceURI:          "aws://123456789012",
	}
	if _, err := collector.NewResourceFact(observation); err != nil {
		t.Fatalf("homed rest API observation must envelope cleanly: %v", err)
	}
}

func TestHomeApigatewayHTTPAPI(t *testing.T) {
	api := awsapigatewayv2types.Api{
		ApiId:        aws.String("h1t2t3"),
		Name:         aws.String("clicks"),
		ProtocolType: awsapigatewayv2types.ProtocolTypeHttp,
		ApiEndpoint:  aws.String("https://h1t2t3.execute-api.us-east-1.amazonaws.com"),
		Tags:         map[string]string{"team": "growth"},
	}
	got := apigatewayV2APIRecord(api, "us-east-1")
	if got.Resource == nil {
		t.Fatal("HTTP API typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceType != "aws_apigatewayv2_api" {
		t.Fatalf("HTTP API resource type = %q", resource.ResourceType)
	}
	if resource.ResourceID != "h1t2t3" || resource.State != "HTTP" {
		t.Fatalf("HTTP API identity = %+v", resource)
	}
	if resource.Attributes["endpoint"] != "https://h1t2t3.execute-api.us-east-1.amazonaws.com" {
		t.Fatalf("HTTP API attributes = %#v", resource.Attributes)
	}
}

func TestHomeApigatewayDomainName(t *testing.T) {
	rest := awsapigatewaytypes.DomainName{
		DomainName:     aws.String("api.example.com"),
		DomainNameArn:  aws.String("arn:aws:apigateway:us-east-1::/domainnames/api.example.com"),
		CertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/cert-1"),
		Tags:           map[string]string{"team": "edge"},
	}
	restGot := apigatewayRestDomainNameRecord(rest, "us-east-1")
	if restGot.Resource == nil {
		t.Fatal("REST domain typed resource missing")
	}
	if restGot.Resource.ResourceType != "aws_apigateway_domain_name" {
		t.Fatalf("REST domain resource type = %q", restGot.Resource.ResourceType)
	}
	restCert := false
	for _, edge := range restGot.Relationships {
		if edge.RelationshipType == "apigateway_domain_uses_acm_certificate" &&
			edge.TargetResourceID == "arn:aws:acm:us-east-1:123456789012:certificate/cert-1" {
			restCert = true
		}
	}
	if !restCert {
		t.Fatalf("REST domain ACM edge missing = %#v", restGot.Relationships)
	}
	v2 := awsapigatewayv2types.DomainName{
		DomainName:    aws.String("clicks.example.com"),
		DomainNameArn: aws.String("arn:aws:apigateway:us-east-1::/domainnames/clicks.example.com/abc"),
		DomainNameConfigurations: []awsapigatewayv2types.DomainNameConfiguration{{
			CertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/cert-2"),
		}},
	}
	v2Got := apigatewayV2DomainNameRecord(v2, "us-east-1")
	if v2Got.Resource == nil {
		t.Fatal("v2 domain typed resource missing")
	}
	if v2Got.Resource.ResourceType != "aws_apigateway_domain_name" {
		t.Fatalf("v2 domain resource type = %q", v2Got.Resource.ResourceType)
	}
	v2Cert := false
	for _, edge := range v2Got.Relationships {
		if edge.RelationshipType == "apigateway_domain_uses_acm_certificate" &&
			edge.TargetResourceID == "arn:aws:acm:us-east-1:123456789012:certificate/cert-2" {
			v2Cert = true
		}
	}
	if !v2Cert {
		t.Fatalf("v2 domain ACM edge missing = %#v", v2Got.Relationships)
	}
}
