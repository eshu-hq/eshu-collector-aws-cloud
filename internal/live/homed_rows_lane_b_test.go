// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func TestHomeSQSQueue(t *testing.T) {
	url := "https://sqs.us-east-1.amazonaws.com/123456789012/orders"
	got := sqsQueueRecord(url, "us-east-1")
	if got.Resource == nil {
		t.Fatal("SQS queue typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceType != "aws_sqs_queue" {
		t.Fatalf("SQS queue resource type = %q", resource.ResourceType)
	}
	if resource.ResourceID != url || resource.Name != "orders" {
		t.Fatalf("SQS queue identity = %+v", resource)
	}
	if resource.Attributes["queue_url"] != url {
		t.Fatalf("SQS queue attributes = %#v", resource.Attributes)
	}
	if !got.TypedOnly {
		t.Fatal("SQS queue row must set TypedOnly")
	}
	if len(got.Relationships) != 0 {
		t.Fatalf("SQS queue relationships = %#v (listing makes no GetQueueAttributes call, so the in-tree DLQ edge stays absent)", got.Relationships)
	}
}

func TestHomeCloudWatchLogsLogGroup(t *testing.T) {
	group := cloudwatchlogstypes.LogGroup{
		Arn:             aws.String("arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/orders:*"),
		LogGroupName:    aws.String("/aws/lambda/orders"),
		KmsKeyId:        aws.String("arn:aws:kms:us-east-1:123456789012:key/aaa111"),
		RetentionInDays: aws.Int32(30),
		StoredBytes:     aws.Int64(1024),
	}
	got := cloudWatchLogsLogGroupRecord(group, "us-east-1")
	if got.Resource == nil {
		t.Fatal("log group typed resource missing")
	}
	if got.Resource.ResourceType != "aws_cloudwatch_logs_log_group" {
		t.Fatalf("log group resource type = %q", got.Resource.ResourceType)
	}
	if got.Resource.Name != "/aws/lambda/orders" {
		t.Fatalf("log group identity = %+v", got.Resource)
	}
	if got.Resource.Attributes["kms_key_id"] != "arn:aws:kms:us-east-1:123456789012:key/aaa111" {
		t.Fatalf("log group attributes = %#v", got.Resource.Attributes)
	}
	if !got.TypedOnly {
		t.Fatal("log group row must set TypedOnly")
	}
	found := false
	for _, edge := range got.Relationships {
		if edge.RelationshipType == "cloudwatch_logs_log_group_uses_kms_key" &&
			edge.TargetResourceID == "arn:aws:kms:us-east-1:123456789012:key/aaa111" {
			found = true
		}
	}
	if !found {
		t.Fatalf("log group KMS edge missing = %#v", got.Relationships)
	}
}

func TestHomeEventBridgeEventBus(t *testing.T) {
	bus := eventbridgetypes.EventBus{
		Arn:         aws.String("arn:aws:events:us-east-1:123456789012:event-bus/orders-bus"),
		Name:        aws.String("orders-bus"),
		Description: aws.String("orders bus"),
	}
	got := eventBridgeEventBusRecord(bus, "us-east-1")
	if got.Resource == nil {
		t.Fatal("event bus typed resource missing")
	}
	if got.Resource.ResourceType != "aws_eventbridge_event_bus" {
		t.Fatalf("event bus resource type = %q", got.Resource.ResourceType)
	}
	if got.Resource.Name != "orders-bus" {
		t.Fatalf("event bus identity = %+v", got.Resource)
	}
	if !got.TypedOnly {
		t.Fatal("event bus row must set TypedOnly")
	}
	if len(got.Relationships) != 0 {
		t.Fatalf("event bus relationships = %#v (in-tree emits none on the bus resource)", got.Relationships)
	}
}

func TestHomeEventBridgeRule(t *testing.T) {
	busARN := "arn:aws:events:us-east-1:123456789012:event-bus/orders-bus"
	rule := eventbridgetypes.Rule{
		Arn:                aws.String("arn:aws:events:us-east-1:123456789012:rule/orders-bus/nightly"),
		Name:               aws.String("nightly"),
		EventBusName:       aws.String("orders-bus"),
		State:              eventbridgetypes.RuleStateEnabled,
		ScheduleExpression: aws.String("cron(0 20 * * ? *)"),
	}
	got := eventBridgeRuleRecord(busARN, "orders-bus", rule, "us-east-1")
	if got.Resource == nil {
		t.Fatal("event rule typed resource missing")
	}
	if got.Resource.ResourceType != "aws_eventbridge_rule" {
		t.Fatalf("event rule resource type = %q", got.Resource.ResourceType)
	}
	if !got.TypedOnly {
		t.Fatal("event rule row must set TypedOnly")
	}
	found := false
	for _, edge := range got.Relationships {
		if edge.RelationshipType == "eventbridge_rule_on_event_bus" &&
			edge.TargetResourceID == busARN {
			found = true
		}
	}
	if !found {
		t.Fatalf("rule on-bus edge missing = %#v", got.Relationships)
	}
}

func TestHomeIAMPolicy(t *testing.T) {
	policy := iamtypes.Policy{
		Arn:              aws.String("arn:aws:iam::123456789012:policy/service/OrdersRead"),
		PolicyName:       aws.String("OrdersRead"),
		Path:             aws.String("/service/"),
		AttachmentCount:  aws.Int32(2),
		DefaultVersionId: aws.String("v3"),
	}
	got := iamPolicyRecord(policy, "us-east-1")
	if got.Resource == nil {
		t.Fatal("IAM policy typed resource missing")
	}
	if got.Resource.ResourceType != "aws_iam_policy" {
		t.Fatalf("IAM policy resource type = %q", got.Resource.ResourceType)
	}
	if got.Resource.Name != "OrdersRead" {
		t.Fatalf("IAM policy identity = %+v", got.Resource)
	}
	if got.Resource.Attributes["default_version_id"] != "v3" {
		t.Fatalf("IAM policy attributes = %#v", got.Resource.Attributes)
	}
	if !got.TypedOnly {
		t.Fatal("IAM policy row must set TypedOnly")
	}
	if len(got.Relationships) != 0 {
		t.Fatalf("IAM policy relationships = %#v (listing reads no policy documents, so no attachment edge)", got.Relationships)
	}
}

func TestHomeIAMInstanceProfile(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/web-role"
	profile := iamtypes.InstanceProfile{
		Arn:                 aws.String("arn:aws:iam::123456789012:instance-profile/web-profile"),
		InstanceProfileName: aws.String("web-profile"),
		Path:                aws.String("/"),
		Roles:               []iamtypes.Role{{Arn: aws.String(roleARN), RoleName: aws.String("web-role")}},
	}
	got := iamInstanceProfileRecord(profile, "us-east-1")
	if got.Resource == nil {
		t.Fatal("instance profile typed resource missing")
	}
	if got.Resource.ResourceType != "aws_iam_instance_profile" {
		t.Fatalf("instance profile resource type = %q", got.Resource.ResourceType)
	}
	if !got.TypedOnly {
		t.Fatal("instance profile row must set TypedOnly")
	}
	found := false
	for _, edge := range got.Relationships {
		if edge.RelationshipType == "iam_role_in_instance_profile" &&
			edge.SourceResourceID == roleARN {
			found = true
		}
	}
	if !found {
		t.Fatalf("instance-profile role edge missing = %#v", got.Relationships)
	}
}

func TestHomeIAMOIDCProvider(t *testing.T) {
	arn := "arn:aws:iam::123456789012:oidc-provider/example.com"
	got := iamOIDCProviderRecord(arn, "https://example.com", []string{"sts.amazonaws.com"}, []string{"abc123"}, "us-east-1")
	if got.Resource == nil {
		t.Fatal("OIDC provider typed resource missing")
	}
	if got.Resource.ResourceType != "aws_iam_oidc_provider" {
		t.Fatalf("OIDC provider resource type = %q", got.Resource.ResourceType)
	}
	if got.Resource.Attributes["client_id_count"] != 1 || got.Resource.Attributes["thumbprint_count"] != 1 {
		t.Fatalf("OIDC provider attributes = %#v", got.Resource.Attributes)
	}
	if !got.TypedOnly {
		t.Fatal("OIDC provider row must set TypedOnly")
	}
}

func TestHomeDynamoDBTable(t *testing.T) {
	table := dynamodbtypes.TableDescription{
		TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/orders"),
		TableName:   aws.String("orders"),
		TableId:     aws.String("abc-123"),
		TableStatus: dynamodbtypes.TableStatusActive,
		SSEDescription: &dynamodbtypes.SSEDescription{
			Status:          dynamodbtypes.SSEStatusEnabled,
			SSEType:         dynamodbtypes.SSETypeKms,
			KMSMasterKeyArn: aws.String("arn:aws:kms:us-east-1:123456789012:key/aaa111"),
		},
	}
	got := dynamoDBTableRecord(table, "us-east-1")
	if got.Resource == nil {
		t.Fatal("DynamoDB table typed resource missing")
	}
	if got.Resource.ResourceType != "aws_dynamodb_table" {
		t.Fatalf("DynamoDB table resource type = %q", got.Resource.ResourceType)
	}
	if got.Resource.Name != "orders" {
		t.Fatalf("DynamoDB table identity = %+v", got.Resource)
	}
	if !got.TypedOnly {
		t.Fatal("DynamoDB table row must set TypedOnly")
	}
	found := false
	for _, edge := range got.Relationships {
		if edge.RelationshipType == "dynamodb_table_uses_kms_key" &&
			edge.TargetResourceID == "arn:aws:kms:us-east-1:123456789012:key/aaa111" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DynamoDB table KMS edge missing = %#v", got.Relationships)
	}
}

func TestHomeSecretsManagerSecret(t *testing.T) {
	secret := secretstypes.SecretListEntry{
		ARN:               aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:orders/db-AbCdEf"),
		Name:              aws.String("orders/db"),
		KmsKeyId:          aws.String("arn:aws:kms:us-east-1:123456789012:key/aaa111"),
		RotationLambdaARN: aws.String("arn:aws:lambda:us-east-1:123456789012:function:orders-rotate"),
		RotationEnabled:   aws.Bool(true),
	}
	got := secretsManagerSecretRecord(secret, "us-east-1")
	if got.Resource == nil {
		t.Fatal("secret typed resource missing")
	}
	if got.Resource.ResourceType != "aws_secretsmanager_secret" {
		t.Fatalf("secret resource type = %q", got.Resource.ResourceType)
	}
	if !got.TypedOnly {
		t.Fatal("secret row must set TypedOnly")
	}
	var kms, rotation bool
	for _, edge := range got.Relationships {
		switch edge.RelationshipType {
		case "secretsmanager_secret_uses_kms_key":
			if edge.TargetResourceID == "arn:aws:kms:us-east-1:123456789012:key/aaa111" {
				kms = true
			}
		case "secretsmanager_secret_uses_rotation_lambda":
			if edge.TargetResourceID == "arn:aws:lambda:us-east-1:123456789012:function:orders-rotate" {
				rotation = true
			}
		}
	}
	if !kms {
		t.Fatalf("secret KMS edge missing = %#v", got.Relationships)
	}
	if !rotation {
		t.Fatalf("secret rotation-lambda edge missing = %#v", got.Relationships)
	}
}

// iamOIDCTestServer serves ListOpenIDConnectProviders plus a scripted
// GetOpenIDConnectProvider outcome: "ok" enriches, an error code denies.
func iamOIDCTestServer(t *testing.T, getOutcome string, calls *map[string]int, arns []string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write fixture response: %v", err)
			}
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		action := r.Form.Get("Action")
		(*calls)[action]++
		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "ListOpenIDConnectProviders":
			members := ""
			for _, arn := range arns {
				members += `<member><Arn>` + arn + `</Arn></member>`
			}
			serve(`<ListOpenIDConnectProvidersResponse><ListOpenIDConnectProvidersResult><OpenIDConnectProviderList>` + members + `</OpenIDConnectProviderList></ListOpenIDConnectProvidersResult></ListOpenIDConnectProvidersResponse>`)
		case "GetOpenIDConnectProvider":
			if getOutcome != "ok" {
				w.WriteHeader(http.StatusForbidden)
				serve(fmt.Sprintf(`<ErrorResponse><Error><Code>%s</Code><Message>denied</Message></Error></ErrorResponse>`, getOutcome))
				return
			}
			serve(`<GetOpenIDConnectProviderResponse><GetOpenIDConnectProviderResult><Url>https://example.com</Url><ClientIDList><member>sts.amazonaws.com</member></ClientIDList><ThumbprintList><member>abc123</member></ThumbprintList></GetOpenIDConnectProviderResult></GetOpenIDConnectProviderResponse>`)
		default:
			t.Errorf("unexpected AWS action %q", action)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func iamOIDCTestClient(t *testing.T, server *httptest.Server) *awsiam.Client {
	t.Helper()
	return awsiam.NewFromConfig(aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	})
}

func TestListIAMOIDCProvidersEnrichRows(t *testing.T) {
	calls := map[string]int{}
	server := iamOIDCTestServer(t, "ok", &calls, []string{"arn:aws:iam::123456789012:oidc-provider/example.com"})
	rows, noDenial, err := listIAMOIDCProviderRecords(context.Background(), iamOIDCTestClient(t, server), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if noDenial != nil {
		t.Fatalf("expected no denial on the enrich path, got %#v", noDenial)
	}
	if len(rows) != 1 {
		t.Fatalf("OIDC rows = %d, want 1", len(rows))
	}
	resource := rows[0].Resource
	if resource == nil {
		t.Fatal("OIDC provider typed resource missing")
	}
	if resource.Attributes["issuer_url"] != "https://example.com" ||
		resource.Attributes["client_id_count"] != 1 ||
		resource.Attributes["thumbprint_count"] != 1 {
		t.Fatalf("OIDC provider enrichment = %#v", resource.Attributes)
	}
	if !rows[0].TypedOnly {
		t.Fatal("OIDC provider row must set TypedOnly")
	}
	if calls["GetOpenIDConnectProvider"] != 1 {
		t.Fatalf("Get calls = %d, want 1", calls["GetOpenIDConnectProvider"])
	}
}

func TestListIAMOIDCProvidersDenialKeepsBareRows(t *testing.T) {
	calls := map[string]int{}
	server := iamOIDCTestServer(t, "AccessDenied", &calls, []string{"arn:aws:iam::123456789012:oidc-provider/example.com"})
	rows, oidcDenial, err := listIAMOIDCProviderRecords(context.Background(), iamOIDCTestClient(t, server), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if oidcDenial == nil || len(oidcDenial.denials) != 1 {
		t.Fatalf("expected one optional denial, got %#v", oidcDenial)
	}
	if oidcDenial.denials[0].operation != "GetOpenIDConnectProvider" {
		t.Fatalf("denial operation = %#v", oidcDenial.denials[0])
	}
	if len(rows) != 1 || rows[0].Resource == nil {
		t.Fatalf("denial must keep the bare typed row, got %#v", rows)
	}
	if rows[0].Resource.Attributes["issuer_url"] != "" {
		t.Fatalf("denied OIDC row must carry an empty URL, got %#v", rows[0].Resource.Attributes)
	}
}

func TestListIAMOIDCProvidersDenialAccumulatesAcrossProviders(t *testing.T) {
	arns := []string{
		"arn:aws:iam::123456789012:oidc-provider/one.example.com",
		"arn:aws:iam::123456789012:oidc-provider/two.example.com",
	}
	calls := map[string]int{}
	server := iamOIDCTestServer(t, "AccessDenied", &calls, arns)
	rows, oidcDenial, err := listIAMOIDCProviderRecords(context.Background(), iamOIDCTestClient(t, server), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("OIDC rows = %d, want 2", len(rows))
	}
	if oidcDenial == nil || len(oidcDenial.denials) != 2 {
		t.Fatalf("expected one denial per provider, got %#v", oidcDenial)
	}
	seen := map[string]bool{}
	for _, denial := range oidcDenial.denials {
		seen[denial.resource] = true
	}
	for _, arn := range arns {
		if !seen[arn] {
			t.Errorf("missing denial for %q (got %v)", arn, seen)
		}
	}
}

// TestHomeCloudWatchLogsLogGroupEnvelopeAdmits is the production regression
// for eshu-hq/eshu#8852: a DescribeLogGroups row carrying the bearer-token
// authentication flag must envelope into an admissible aws_resource fact.
// The lane record builder alone never runs the SDK share-safe guard, so a
// record-level test stays green while every live claim exits 1 with
// launch_failure (proven in ops-qa: the full-scope replay fails on
// attributes.bearer_token_authentication_enabled).
func TestHomeCloudWatchLogsLogGroupEnvelopeAdmits(t *testing.T) {
	group := cloudwatchlogstypes.LogGroup{
		Arn:                              aws.String("arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/orders:*"),
		LogGroupName:                     aws.String("/aws/lambda/orders"),
		KmsKeyId:                         aws.String("arn:aws:kms:us-east-1:123456789012:key/aaa111"),
		RetentionInDays:                  aws.Int32(30),
		BearerTokenAuthenticationEnabled: aws.Bool(true),
	}
	got := cloudWatchLogsLogGroupRecord(group, "us-east-1")
	if got.Resource == nil {
		t.Fatal("log group typed resource missing")
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
		t.Fatalf("homed log-group observation must envelope cleanly: %v", err)
	}
}
