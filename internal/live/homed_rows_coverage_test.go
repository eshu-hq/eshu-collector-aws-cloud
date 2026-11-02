// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsapigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	awselbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// coverageDeepEqual asserts concrete helper output values for the homed-row
// coverage tests below.
func coverageDeepEqual(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %#v, want %#v", what, got, want)
	}
}

func TestCoverageElbv2Certificates(t *testing.T) {
	coverageDeepEqual(t, "nil certificates", elbv2Certificates(nil), []string(nil))
	coverageDeepEqual(t, "empty certificates", elbv2Certificates([]awselbv2types.Certificate{}), []string(nil))
	got := elbv2Certificates([]awselbv2types.Certificate{
		{CertificateArn: aws.String("arn:aws:acm:us-east-1:123:certificate/first")},
		{},
		{CertificateArn: aws.String("  arn:aws:acm:us-east-1:123:certificate/second  ")},
	})
	coverageDeepEqual(t, "multi certificates", got, []string{
		"arn:aws:acm:us-east-1:123:certificate/first",
		"arn:aws:acm:us-east-1:123:certificate/second",
	})
}

func TestCoverageElbv2ActionTargetGroups(t *testing.T) {
	coverageDeepEqual(t, "empty action", elbv2ActionTargetGroups(awselbv2types.Action{}), []elbv2TargetGroupRef(nil))
	direct := elbv2ActionTargetGroups(awselbv2types.Action{
		Type: "forward", TargetGroupArn: aws.String("arn:tg:one"),
	})
	coverageDeepEqual(t, "direct target", direct, []elbv2TargetGroupRef{{ARN: "arn:tg:one"}})
	weighted := elbv2ActionTargetGroups(awselbv2types.Action{
		Type: "forward", TargetGroupArn: aws.String("arn:tg:one"),
		ForwardConfig: &awselbv2types.ForwardActionConfig{TargetGroups: []awselbv2types.TargetGroupTuple{
			{TargetGroupArn: aws.String("arn:tg:one"), Weight: aws.Int32(50)},
			{TargetGroupArn: aws.String("arn:tg:two"), Weight: aws.Int32(50)},
			{TargetGroupArn: aws.String("  ")},
		}},
	})
	coverageDeepEqual(t, "weighted dedup", weighted, []elbv2TargetGroupRef{
		{ARN: "arn:tg:one"},
		{ARN: "arn:tg:two", Weight: 50},
	})
}

func TestCoverageElbv2WeightedTargetGroupMaps(t *testing.T) {
	coverageDeepEqual(t, "nil config", elbv2WeightedTargetGroupMaps(nil), []map[string]any(nil))
	coverageDeepEqual(t, "empty groups", elbv2WeightedTargetGroupMaps(&awselbv2types.ForwardActionConfig{}), []map[string]any(nil))
	got := elbv2WeightedTargetGroupMaps(&awselbv2types.ForwardActionConfig{TargetGroups: []awselbv2types.TargetGroupTuple{
		{TargetGroupArn: aws.String("arn:tg:one"), Weight: aws.Int32(80)},
		{TargetGroupArn: aws.String("arn:tg:two"), Weight: aws.Int32(20)},
	}})
	coverageDeepEqual(t, "weighted groups", got, []map[string]any{
		{"target_group_arn": "arn:tg:one", "weight": int32(80)},
		{"target_group_arn": "arn:tg:two", "weight": int32(20)},
	})
}

func TestCoverageElbv2ActionMaps(t *testing.T) {
	coverageDeepEqual(t, "no actions", elbv2ActionMaps(nil), []map[string]any(nil))
	got := elbv2ActionMaps([]awselbv2types.Action{
		{
			Type: "redirect", Order: aws.Int32(1),
			RedirectConfig: &awselbv2types.RedirectActionConfig{
				Host: aws.String("example.com"), Path: aws.String("/login"),
				Port: aws.String("443"), Protocol: aws.String("HTTPS"),
				Query: aws.String("next=#{path}"), StatusCode: "HTTP_301",
			},
		},
		{
			Type: "fixed-response", TargetGroupArn: aws.String("arn:tg:one"),
			FixedResponseConfig: &awselbv2types.FixedResponseActionConfig{
				ContentType: aws.String("text/plain"), MessageBody: aws.String("blocked"), StatusCode: aws.String("403"),
			},
		},
		{
			Type: "forward",
			ForwardConfig: &awselbv2types.ForwardActionConfig{TargetGroups: []awselbv2types.TargetGroupTuple{
				{TargetGroupArn: aws.String("arn:tg:one"), Weight: aws.Int32(80)},
				{TargetGroupArn: aws.String("arn:tg:two"), Weight: aws.Int32(20)},
			}},
		},
	})
	if len(got) != 3 {
		t.Fatalf("action maps = %d, want 3", len(got))
	}
	coverageDeepEqual(t, "redirect map", got[0]["redirect"], map[string]any{
		"host": "example.com", "path": "/login", "port": "443",
		"protocol": "HTTPS", "query": "next=#{path}", "status_code": "HTTP_301",
	})
	coverageDeepEqual(t, "redirect order", got[0]["order"], int32(1))
	coverageDeepEqual(t, "fixed map", got[1]["fixed_response"], map[string]any{
		"content_type": "text/plain", "message_body": "blocked", "status_code": "403",
	})
	coverageDeepEqual(t, "fixed target", got[1]["target_group_arn"], "arn:tg:one")
	forward, ok := got[2]["forward_target_groups"].([]map[string]any)
	if !ok || len(forward) != 2 {
		t.Fatalf("forward target groups = %#v, want 2 entries", got[2]["forward_target_groups"])
	}
	coverageDeepEqual(t, "forward weight", forward[1]["weight"], int32(20))
}

func TestCoverageElbv2ConditionMaps(t *testing.T) {
	coverageDeepEqual(t, "no conditions", elbv2ConditionMaps(nil), []map[string]any(nil))
	got := elbv2ConditionMaps([]awselbv2types.RuleCondition{
		{
			Field:            aws.String("host-header"),
			HostHeaderConfig: &awselbv2types.HostHeaderConditionConfig{Values: []string{"a.example.com", "b.example.com"}},
		},
		{
			Field: aws.String("http-header"),
			HttpHeaderConfig: &awselbv2types.HttpHeaderConditionConfig{
				HttpHeaderName: aws.String("X-Tenant"), Values: []string{"blue", "green"},
			},
		},
		{
			Field:                   aws.String("http-request-method"),
			HttpRequestMethodConfig: &awselbv2types.HttpRequestMethodConditionConfig{Values: []string{"GET", "POST"}},
		},
		{
			Field:             aws.String("path-pattern"),
			PathPatternConfig: &awselbv2types.PathPatternConditionConfig{Values: []string{"/api/*"}},
		},
		{
			Field: aws.String("query-string"),
			QueryStringConfig: &awselbv2types.QueryStringConditionConfig{Values: []awselbv2types.QueryStringKeyValuePair{
				{Key: aws.String("team"), Value: aws.String("core")},
				{Key: aws.String("empty"), Value: aws.String("")},
			}},
		},
		{
			Field:          aws.String("source-ip"),
			SourceIpConfig: &awselbv2types.SourceIpConditionConfig{Values: []string{"10.0.0.0/8"}},
			Values:         []string{"legacy"},
		},
	})
	if len(got) != 6 {
		t.Fatalf("condition maps = %d, want 6", len(got))
	}
	coverageDeepEqual(t, "host header", got[0]["host_header_values"], []string{"a.example.com", "b.example.com"})
	coverageDeepEqual(t, "http header name", got[1]["http_header_name"], "X-Tenant")
	coverageDeepEqual(t, "http header values", got[1]["http_header_values"], []string{"blue", "green"})
	coverageDeepEqual(t, "methods", got[2]["http_request_methods"], []string{"GET", "POST"})
	coverageDeepEqual(t, "path patterns", got[3]["path_pattern_values"], []string{"/api/*"})
	coverageDeepEqual(t, "query strings", got[4]["query_strings"], []map[string]string{
		{"key": "team", "value": "core"}, {"key": "empty", "value": ""},
	})
	coverageDeepEqual(t, "source ips", got[5]["source_ip_values"], []string{"10.0.0.0/8"})
}

func TestCoverageElbv2ConditionValueHelpers(t *testing.T) {
	var empty awselbv2types.RuleCondition
	coverageDeepEqual(t, "host header nil", elbv2HostHeaderValues(empty), []string(nil))
	coverageDeepEqual(t, "http header name empty", elbv2HTTPHeaderName(empty), "")
	coverageDeepEqual(t, "http header values nil", elbv2HTTPHeaderValues(empty), []string(nil))
	coverageDeepEqual(t, "methods nil", elbv2HTTPRequestMethods(empty), []string(nil))
	coverageDeepEqual(t, "path patterns nil", elbv2PathPatternValues(empty), []string(nil))
	coverageDeepEqual(t, "query strings nil", elbv2QueryStrings(empty), []map[string]string(nil))
	coverageDeepEqual(t, "query strings empty", elbv2QueryStrings(awselbv2types.RuleCondition{
		QueryStringConfig: &awselbv2types.QueryStringConditionConfig{},
	}), []map[string]string(nil))
	coverageDeepEqual(t, "source ips nil", elbv2SourceIPValues(empty), []string(nil))
}

func TestCoverageElbv2HealthCheckMap(t *testing.T) {
	plain := elbv2HealthCheckMap(awselbv2types.TargetGroup{})
	coverageDeepEqual(t, "matcher default", plain["matcher"], "")
	coverageDeepEqual(t, "enabled default", plain["enabled"], false)
	httpCode := elbv2HealthCheckMap(awselbv2types.TargetGroup{
		Matcher: &awselbv2types.Matcher{HttpCode: aws.String("200-299")},
	})
	coverageDeepEqual(t, "http matcher", httpCode["matcher"], "200-299")
}

func TestCoverageElbv2FirstNonEmptyAndTime(t *testing.T) {
	coverageDeepEqual(t, "first non-empty", elbv2FirstNonEmpty("", "  ", "a", "b"), "a")
	coverageDeepEqual(t, "all blank", elbv2FirstNonEmpty("", "   "), "")
	coverageDeepEqual(t, "nil time", elbv2TimeOrNil(nil), nil)
	coverageDeepEqual(t, "zero time", elbv2TimeOrNil(&time.Time{}), nil)
	stamp := time.Date(2024, 5, 1, 12, 0, 0, 0, time.FixedZone("PST", -8*3600))
	gotTime, ok := elbv2TimeOrNil(&stamp).(time.Time)
	if !ok {
		t.Fatal("time helper must return a timestamp")
	}
	coverageDeepEqual(t, "time instant", gotTime.Unix(), stamp.Unix())
	coverageDeepEqual(t, "time zone", gotTime.Location().String(), "UTC")
}

func TestCoverageElbv2RouteEdges(t *testing.T) {
	seed := []awselbv2types.Action{{Type: "forward", TargetGroupArn: aws.String("arn:tg:one")}}
	if got := elbv2RouteEdges("us-east-1", "  ", "arn:lb", "default_action", "", "", seed); got != nil {
		t.Fatalf("empty listener edges = %#v, want nil", got)
	}
	edges := elbv2RouteEdges("us-east-1", "arn:listener", "arn:lb", "default_action", "", "", []awselbv2types.Action{
		{Type: "forward", TargetGroupArn: aws.String("arn:tg:one")},
		{Type: "forward", ForwardConfig: &awselbv2types.ForwardActionConfig{TargetGroups: []awselbv2types.TargetGroupTuple{
			{TargetGroupArn: aws.String("arn:tg:one"), Weight: aws.Int32(30)},
			{TargetGroupArn: aws.String("arn:tg:two"), Weight: aws.Int32(70)},
		}}},
	})
	if len(edges) != 2 {
		t.Fatalf("route edges = %d, want 2", len(edges))
	}
	coverageDeepEqual(t, "first target", edges[0].TargetResourceID, "arn:tg:one")
	routes, ok := edges[0].Attributes["routes"].([]map[string]any)
	if !ok || len(routes) != 2 {
		t.Fatalf("grouped routes = %#v, want 2 entries", edges[0].Attributes["routes"])
	}
	coverageDeepEqual(t, "route source", routes[0]["route_source"], "default_action")
	coverageDeepEqual(t, "route weight", routes[1]["target_weight"], int32(30))
	coverageDeepEqual(t, "edge record", edges[0].SourceRecordID, "arn:listener#target-group#arn:tg:one")
}

func TestCoverageElbv2TargetGroupRecord(t *testing.T) {
	blank := elbv2TargetGroupRecord(awselbv2types.TargetGroup{
		TargetGroupArn: aws.String("arn:tg:one"), TargetGroupName: aws.String("one"),
		LoadBalancerArns: []string{"", "  "},
	}, "us-east-1")
	if len(blank.Relationships) != 0 {
		t.Fatalf("blank load balancer ARNs must yield no edges, got %#v", blank.Relationships)
	}
	mixed := elbv2TargetGroupRecord(awselbv2types.TargetGroup{
		TargetGroupArn: aws.String("arn:tg:one"), TargetGroupName: aws.String("one"),
		LoadBalancerArns: []string{"", "arn:lb:one"},
	}, "us-east-1")
	if len(mixed.Relationships) != 1 {
		t.Fatalf("target group edges = %d, want 1", len(mixed.Relationships))
	}
	coverageDeepEqual(t, "edge target", mixed.Relationships[0].TargetResourceID, "arn:lb:one")
	coverageDeepEqual(t, "edge record", mixed.Relationships[0].SourceRecordID, "arn:tg:one#load-balancer#arn:lb:one")
	noARN := elbv2TargetGroupRecord(awselbv2types.TargetGroup{
		TargetGroupName: aws.String("ghost"), LoadBalancerArns: []string{"arn:lb:one"},
	}, "us-east-1")
	if len(noARN.Relationships) != 0 {
		t.Fatalf("empty group ARN must yield no edges, got %#v", noARN.Relationships)
	}
}

func TestCoverageApigatewayARNs(t *testing.T) {
	coverageDeepEqual(t, "rest empty", apigatewayRestAPIARN("us-east-1", "  "), "")
	coverageDeepEqual(t, "v2 empty", apigatewayV2APIARN("us-east-1", ""), "")
	coverageDeepEqual(t, "rest arn", apigatewayRestAPIARN("us-east-1", "api123"), "arn:aws:apigateway:us-east-1::/restapis/api123")
	coverageDeepEqual(t, "v2 arn", apigatewayV2APIARN("  us-east-1  ", "api456"), "arn:aws:apigateway:us-east-1::/apis/api456")
}

func TestCoverageApigatewayFirstV2Helpers(t *testing.T) {
	coverageDeepEqual(t, "status empty", apigatewayFirstV2DomainStatus(nil), "")
	coverageDeepEqual(t, "domain name empty", apigatewayFirstV2APIGatewayDomainName(nil), "")
	coverageDeepEqual(t, "hosted zone empty", apigatewayFirstV2HostedZoneID([]awsapigatewayv2types.DomainNameConfiguration{}), "")
	coverageDeepEqual(t, "security policy empty", apigatewayFirstV2SecurityPolicy(nil), "")
	configs := []awsapigatewayv2types.DomainNameConfiguration{
		{},
		{
			DomainNameStatus: "AVAILABLE", EndpointType: "  ",
			ApiGatewayDomainName: aws.String("d-abc.execute-api.us-east-1.amazonaws.com"),
			HostedZoneId:         aws.String("Z123"), SecurityPolicy: "TLS_1_2",
		},
		{EndpointType: "REGIONAL"},
	}
	coverageDeepEqual(t, "status", apigatewayFirstV2DomainStatus(configs), "AVAILABLE")
	coverageDeepEqual(t, "domain name", apigatewayFirstV2APIGatewayDomainName(configs), "d-abc.execute-api.us-east-1.amazonaws.com")
	coverageDeepEqual(t, "hosted zone", apigatewayFirstV2HostedZoneID(configs), "Z123")
	coverageDeepEqual(t, "security policy", apigatewayFirstV2SecurityPolicy(configs), "TLS_1_2")
	coverageDeepEqual(t, "endpoint types", apigatewayV2DomainEndpointTypes(configs), []string{"REGIONAL"})
}

func TestCoverageApigatewayClones(t *testing.T) {
	coverageDeepEqual(t, "map nil", apigatewayCloneStringMap(nil), map[string]string(nil))
	coverageDeepEqual(t, "map blanks", apigatewayCloneStringMap(map[string]string{"  ": "x", "": "y"}), map[string]string(nil))
	coverageDeepEqual(t, "map kept", apigatewayCloneStringMap(map[string]string{" team ": "core", "empty": ""}),
		map[string]string{"team": "core", "empty": ""})
	coverageDeepEqual(t, "strings nil", apigatewayCloneStrings(nil), []string(nil))
	coverageDeepEqual(t, "strings blanks", apigatewayCloneStrings([]string{"", "  "}), []string(nil))
	coverageDeepEqual(t, "strings dedup", apigatewayCloneStrings([]string{" b ", "a", "b", "", "a "}), []string{"b", "a"})
	coverageDeepEqual(t, "bool nil", apigatewayBoolOrNil(nil), nil)
	coverageDeepEqual(t, "bool kept", apigatewayBoolOrNil(aws.Bool(true)), true)
	coverageDeepEqual(t, "time nil", apigatewayTimeOrNil(nil), nil)
	coverageDeepEqual(t, "time zero", apigatewayTimeOrNil(&time.Time{}), nil)
	stamp := time.Date(2024, 2, 29, 8, 30, 0, 0, time.FixedZone("X", 3600))
	gotTime, ok := apigatewayTimeOrNil(&stamp).(time.Time)
	if !ok {
		t.Fatal("time helper must return a timestamp")
	}
	coverageDeepEqual(t, "time instant", gotTime.Unix(), stamp.Unix())
	coverageDeepEqual(t, "first non-empty", apigatewayFirstNonEmpty(" ", "", "x", "y"), "x")
	coverageDeepEqual(t, "first all blank", apigatewayFirstNonEmpty("", "  "), "")
}

func TestCoverageApigatewayDomainCertificateEdges(t *testing.T) {
	if got := apigatewayDomainCertificateEdges("us-east-1", "  ", "arn:domain", "v2", "example.com", []string{"arn:cert"}); got != nil {
		t.Fatalf("empty source edges = %#v, want nil", got)
	}
	edges := apigatewayDomainCertificateEdges("us-east-1", "example.com", "arn:domain", "v2", "example.com",
		[]string{"arn:cert:one", "  ", "arn:cert:one", "arn:cert:two"})
	if len(edges) != 2 {
		t.Fatalf("certificate edges = %d, want 2", len(edges))
	}
	coverageDeepEqual(t, "edge target", edges[0].TargetResourceID, "arn:cert:one")
	coverageDeepEqual(t, "edge kind", edges[0].Attributes["api_kind"], "v2")
	coverageDeepEqual(t, "edge domain", edges[0].Attributes["domain"], "example.com")
	coverageDeepEqual(t, "edge record", edges[0].SourceRecordID, "example.com->arn:cert:one")
	coverageDeepEqual(t, "second target", edges[1].TargetResourceID, "arn:cert:two")
}

func TestCoverageNetdataHelpers(t *testing.T) {
	coverageDeepEqual(t, "first non-empty", netdataFirstNonEmpty("", " a ", "b"), "a")
	coverageDeepEqual(t, "first all blank", netdataFirstNonEmpty(" ", ""), "")
	coverageDeepEqual(t, "time nil", netdataTimeOrNil(nil), nil)
	coverageDeepEqual(t, "time zero", netdataTimeOrNil(&time.Time{}), nil)
	stamp := time.Date(2024, 5, 1, 12, 0, 0, 0, time.FixedZone("PST", -8*3600))
	gotTime, ok := netdataTimeOrNil(&stamp).(time.Time)
	if !ok {
		t.Fatal("time helper must return a timestamp")
	}
	coverageDeepEqual(t, "time instant", gotTime.Unix(), stamp.Unix())
	coverageDeepEqual(t, "millis nil", netdataTimeMillis(nil), nil)
	millis := int64(1700000000000)
	gotMillis, ok := netdataTimeMillis(&millis).(time.Time)
	if !ok {
		t.Fatal("millis helper must return a timestamp")
	}
	coverageDeepEqual(t, "millis value", gotMillis.UnixMilli(), millis)
	coverageDeepEqual(t, "tags nil", netdataIAMTags(nil), map[string]string(nil))
	coverageDeepEqual(t, "tags blank", netdataIAMTags([]iamtypes.Tag{{Key: aws.String("  ")}, {}}), map[string]string(nil))
	coverageDeepEqual(t, "tags kept", netdataIAMTags([]iamtypes.Tag{
		{Key: aws.String(" team "), Value: aws.String("core")},
		{Key: aws.String("empty")},
		{Key: aws.String("")},
	}), map[string]string{"team": "core", "empty": ""})
}

func TestCoverageEventBridgeRuleRecord(t *testing.T) {
	bare := eventBridgeRuleRecord("", "", eventbridgetypes.Rule{}, "us-east-1")
	if len(bare.Relationships) != 0 {
		t.Fatalf("identity-less rule must carry no edges, got %#v", bare.Relationships)
	}
	coverageDeepEqual(t, "bare resource", bare.Resource.ResourceID, "")
	fallback := eventBridgeRuleRecord("", "mybus", eventbridgetypes.Rule{Name: aws.String("myrule")}, "us-east-1")
	coverageDeepEqual(t, "fallback id", fallback.Resource.ResourceID, "mybus/myrule")
	if len(fallback.Relationships) != 1 {
		t.Fatalf("rule edges = %d, want 1", len(fallback.Relationships))
	}
	coverageDeepEqual(t, "bus edge", fallback.Relationships[0].TargetResourceID, "mybus")
	coverageDeepEqual(t, "event bus name", fallback.Resource.Attributes["event_bus_name"], "mybus")
}

func TestCoverageIAMInstanceProfileRecord(t *testing.T) {
	ghost := iamInstanceProfileRecord(iamtypes.InstanceProfile{
		InstanceProfileName: aws.String("ghost"),
		Roles:               []iamtypes.Role{{Arn: aws.String("arn:role:one")}, {Arn: aws.String("  ")}},
	}, "us-east-1")
	if len(ghost.Relationships) != 0 {
		t.Fatalf("arn-less profile must carry no edges, got %#v", ghost.Relationships)
	}
	two := iamInstanceProfileRecord(iamtypes.InstanceProfile{
		Arn: aws.String("arn:profile"), InstanceProfileName: aws.String("prof"),
		Roles: []iamtypes.Role{{Arn: aws.String("arn:role:one")}, {Arn: aws.String("arn:role:two")}, {}},
	}, "us-east-1")
	if len(two.Relationships) != 2 {
		t.Fatalf("profile edges = %d, want 2", len(two.Relationships))
	}
	coverageDeepEqual(t, "edge record", two.Relationships[0].SourceRecordID, "arn:role:one#instance-profile#arn:profile")
	coverageDeepEqual(t, "role arns", two.Resource.Attributes["role_arns"], []string{"arn:role:one", "arn:role:two"})
}

func TestCoverageDynamoDBTableRecord(t *testing.T) {
	plain := dynamoDBTableRecord(dynamodbtypes.TableDescription{
		TableArn: aws.String("arn:table"), TableName: aws.String("orders"),
		TableStatus: "ACTIVE", ItemCount: aws.Int64(7),
	}, "us-east-1")
	coverageDeepEqual(t, "billing default", plain.Resource.Attributes["billing_mode"], "")
	if len(plain.Relationships) != 0 {
		t.Fatalf("key-less table must carry no edges, got %#v", plain.Relationships)
	}
	withKeys := dynamoDBTableRecord(dynamodbtypes.TableDescription{
		TableArn: aws.String("arn:table"), TableName: aws.String("orders"), TableStatus: "ACTIVE",
		BillingModeSummary: &dynamodbtypes.BillingModeSummary{BillingMode: "PAY_PER_REQUEST"},
		SSEDescription: &dynamodbtypes.SSEDescription{
			Status: "ENABLED", SSEType: "KMS", KMSMasterKeyArn: aws.String("arn:kms:key"),
		},
	}, "us-east-1")
	coverageDeepEqual(t, "billing mode", withKeys.Resource.Attributes["billing_mode"], "PAY_PER_REQUEST")
	coverageDeepEqual(t, "sse status", withKeys.Resource.Attributes["sse_status"], "ENABLED")
	if len(withKeys.Relationships) != 1 {
		t.Fatalf("table edges = %d, want 1", len(withKeys.Relationships))
	}
	coverageDeepEqual(t, "kms edge", withKeys.Relationships[0].TargetResourceID, "arn:kms:key")
}

func TestCoverageSecretsManagerSecretRecord(t *testing.T) {
	bare := secretsManagerSecretRecord(secretstypes.SecretListEntry{}, "us-east-1")
	if len(bare.Relationships) != 0 {
		t.Fatalf("identity-less secret must carry no edges, got %#v", bare.Relationships)
	}
	kmsOnly := secretsManagerSecretRecord(secretstypes.SecretListEntry{
		ARN: aws.String("arn:secret"), Name: aws.String("s"), KmsKeyId: aws.String("alias/key"),
	}, "us-east-1")
	if len(kmsOnly.Relationships) != 1 {
		t.Fatalf("kms secret edges = %d, want 1", len(kmsOnly.Relationships))
	}
	coverageDeepEqual(t, "kms target", kmsOnly.Relationships[0].TargetResourceID, "alias/key")
	rotationOnly := secretsManagerSecretRecord(secretstypes.SecretListEntry{
		ARN: aws.String("arn:secret"), Name: aws.String("s"),
		RotationEnabled: aws.Bool(true), RotationLambdaARN: aws.String("arn:lambda:fn"),
	}, "us-east-1")
	if len(rotationOnly.Relationships) != 1 {
		t.Fatalf("rotation secret edges = %d, want 1", len(rotationOnly.Relationships))
	}
	coverageDeepEqual(t, "rotation target", rotationOnly.Relationships[0].TargetResourceID, "arn:lambda:fn")
	both := secretsManagerSecretRecord(secretstypes.SecretListEntry{
		ARN: aws.String("arn:secret"), Name: aws.String("s"),
		KmsKeyId:        aws.String("arn:kms:key"),
		RotationEnabled: aws.Bool(true), RotationLambdaARN: aws.String("arn:lambda:fn"),
	}, "us-east-1")
	if len(both.Relationships) != 2 {
		t.Fatalf("full secret edges = %d, want 2", len(both.Relationships))
	}
	coverageDeepEqual(t, "rotation enabled", both.Resource.Attributes["rotation_enabled"], true)
}

// coverageOIDCThrottledClient serves ListOpenIDConnectProviders with one
// provider whose GetOpenIDConnectProvider call fails with a non-denial
// ThrottlingException, exercising the fatal Get path.
func coverageOIDCThrottledClient(t *testing.T) *awsiam.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse fixture form: %v", err)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "ListOpenIDConnectProviders":
			if _, err := w.Write([]byte(`<ListOpenIDConnectProvidersResponse><ListOpenIDConnectProvidersResult><OpenIDConnectProviderList><member><Arn>arn:aws:iam::123456789012:oidc-provider/example.com</Arn></member></OpenIDConnectProviderList></ListOpenIDConnectProvidersResult></ListOpenIDConnectProvidersResponse>`)); err != nil {
				t.Errorf("write fixture response: %v", err)
			}
		case "GetOpenIDConnectProvider":
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(`<ErrorResponse><Error><Code>ThrottlingException</Code><Message>rate exceeded</Message></Error></ErrorResponse>`)); err != nil {
				t.Errorf("write fixture response: %v", err)
			}
		default:
			t.Errorf("unexpected AWS action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	return awsiam.NewFromConfig(aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	})
}

func TestCoverageListIAMOIDCFatalGet(t *testing.T) {
	rows, denial, err := listIAMOIDCProviderRecords(context.Background(), coverageOIDCThrottledClient(t), "us-east-1")
	if err == nil {
		t.Fatal("throttled Get must fail the OIDC listing")
	}
	if !strings.Contains(err.Error(), "iam get OIDC provider") {
		t.Fatalf("fatal error = %q, want the iam-get-OIDC-provider wrap", err.Error())
	}
	if len(rows) != 0 {
		t.Fatalf("fatal Get must return no rows, got %#v", rows)
	}
	if denial != nil {
		t.Fatalf("fatal Get must return no denial, got %#v", denial)
	}
}
