// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
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
