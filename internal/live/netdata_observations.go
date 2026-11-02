// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// The net-data resource and relationship types reuse the satellite catalog
// constants (pinned to the in-tree catalog strings by the catalog tests);
// the parity note in the lane report locks each value against the in-tree
// oracle key. The KMS target type keeps the in-tree "aws_kms_key" literal,
// matching the kms_key.go sibling.
const (
	sqsQueueResourceType = catalog.ResourceTypeSQSQueue

	cloudWatchLogsLogGroupResourceType                 = catalog.ResourceTypeCloudWatchLogsLogGroup
	cloudWatchLogsLogGroupUsesKMSKeyRelationship       = catalog.RelationshipCloudWatchLogsLogGroupUsesKMSKey
	eventBridgeEventBusResourceType                    = catalog.ResourceTypeEventBridgeEventBus
	eventBridgeRuleResourceType                        = catalog.ResourceTypeEventBridgeRule
	eventBridgeRuleOnEventBusRelationship              = catalog.RelationshipEventBridgeRuleOnEventBus
	iamPolicyResourceType                              = catalog.ResourceTypeIAMPolicy
	iamInstanceProfileResourceType                     = catalog.ResourceTypeIAMInstanceProfile
	iamRoleInInstanceProfileRelationship               = catalog.RelationshipIAMRoleInInstanceProfile
	iamOIDCProviderResourceType                        = catalog.ResourceTypeEKSOIDCProvider
	dynamoDBTableResourceType                          = catalog.ResourceTypeDynamoDBTable
	dynamoDBTableUsesKMSKeyRelationship                = catalog.RelationshipDynamoDBTableUsesKMSKey
	secretsManagerSecretResourceType                   = catalog.ResourceTypeSecretsManagerSecret
	secretsManagerSecretUsesKMSKeyRelationship         = catalog.RelationshipSecretsManagerSecretUsesKMSKey
	secretsManagerSecretUsesRotationLambdaRelationship = catalog.RelationshipSecretsManagerSecretUsesRotationLambda
)

// sqsQueueRecord gives a ListQueues row its typed home. The listing reports
// only the queue URL, so identity and the queue_url/name attributes mirror
// the in-tree queueObservation fields the list read can fill. The listing
// makes no GetQueueAttributes call, so redrive attributes stay empty and the
// in-tree dead-letter edge stays absent.
func sqsQueueRecord(queueURL, region string) collector.Record {
	url := strings.TrimSpace(queueURL)
	name := lastSegment(url, "/")
	row := record(url, catalog.ServiceSQS, region, name, "queue")
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceSQS,
		ResourceType: sqsQueueResourceType,
		ResourceID:   url,
		Name:         name,
		Attributes: map[string]any{
			"queue_name": name,
			"queue_url":  url,
		},
		CorrelationAnchors: []string{url, name},
		SourceRecordID:     url,
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

// cloudWatchLogsLogGroupRecord gives a DescribeLogGroups row its typed home
// and the KMS edge the in-tree logGroupEnvelopes emits. The translation
// mirrors the in-tree logGroupObservation fields the describe read returns
// inline; tags stay nil because the listing makes no ListTagsForResource
// call.
func cloudWatchLogsLogGroupRecord(group cloudwatchlogstypes.LogGroup, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(group.Arn))
	name := strings.TrimSpace(aws.ToString(group.LogGroupName))
	row := record(arn, catalog.ServiceCloudWatchLogs, region, name, "log-group")
	resourceID := netdataFirstNonEmpty(arn, name)
	kmsKeyID := strings.TrimSpace(aws.ToString(group.KmsKeyId))
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceCloudWatchLogs,
		ResourceType: cloudWatchLogsLogGroupResourceType,
		ResourceID:   resourceID,
		Name:         name,
		ARN:          arn,
		Attributes: map[string]any{
			"creation_time":                       netdataTimeMillis(group.CreationTime),
			"retention_in_days":                   aws.ToInt32(group.RetentionInDays),
			"stored_bytes":                        aws.ToInt64(group.StoredBytes),
			"metric_filter_count":                 aws.ToInt32(group.MetricFilterCount),
			"log_group_class":                     strings.TrimSpace(string(group.LogGroupClass)),
			"kms_key_id":                          kmsKeyID,
			"deletion_protected":                  aws.ToBool(group.DeletionProtectionEnabled),
			"bearer_token_authentication_enabled": aws.ToBool(group.BearerTokenAuthenticationEnabled),
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	if resourceID == "" || kmsKeyID == "" {
		return row
	}
	targetARN := ""
	if strings.HasPrefix(kmsKeyID, "arn:") {
		targetARN = kmsKeyID
	}
	row.Relationships = append(row.Relationships, collector.LiveRelationship{
		Region: region, ServiceKind: catalog.ServiceCloudWatchLogs,
		RelationshipType: cloudWatchLogsLogGroupUsesKMSKeyRelationship,
		SourceResourceID: resourceID, SourceARN: arn,
		TargetResourceID: kmsKeyID, TargetARN: targetARN,
		TargetType:     "aws_kms_key",
		SourceRecordID: resourceID + "->" + cloudWatchLogsLogGroupUsesKMSKeyRelationship + ":" + kmsKeyID,
	})
	return row
}

// eventBridgeEventBusRecord gives a ListEventBuses row its typed home. The
// translation mirrors the in-tree eventBusObservation fields the list read
// returns inline. The in-tree scanner emits no relationship on the bus
// resource itself.
func eventBridgeEventBusRecord(bus eventbridgetypes.EventBus, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(bus.Arn))
	name := strings.TrimSpace(aws.ToString(bus.Name))
	row := record(arn, catalog.ServiceEventBridge, region, name, "event-bus")
	resourceID := netdataFirstNonEmpty(arn, name)
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceEventBridge,
		ResourceType: eventBridgeEventBusResourceType,
		ResourceID:   resourceID,
		Name:         name,
		ARN:          arn,
		Attributes: map[string]any{
			"description":        strings.TrimSpace(aws.ToString(bus.Description)),
			"creation_time":      netdataTimeOrNil(bus.CreationTime),
			"last_modified_time": netdataTimeOrNil(bus.LastModifiedTime),
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

// eventBridgeRuleRecord gives a ListRules row its typed home plus the
// rule-on-bus edge the in-tree scanner emits. The SDK Rule carries no bus
// ARN, so the caller passes the bus identity of the list request. The
// translation mirrors the in-tree ruleObservation fields the list read
// returns inline; rule targets need a ListTargets call the listing does not
// make, so target edges stay absent.
func eventBridgeRuleRecord(busARN, busName string, rule eventbridgetypes.Rule, region string) collector.Record {
	busARN = strings.TrimSpace(busARN)
	busName = strings.TrimSpace(busName)
	ruleARN := strings.TrimSpace(aws.ToString(rule.Arn))
	ruleName := strings.TrimSpace(aws.ToString(rule.Name))
	eventBusName := strings.TrimSpace(aws.ToString(rule.EventBusName))
	if eventBusName == "" {
		eventBusName = busName
	}
	row := record(ruleARN, catalog.ServiceEventBridge, region, ruleName, "rule")
	resourceID := netdataFirstNonEmpty(ruleARN, netdataJoinNonEmpty("/", eventBusName, ruleName), ruleName)
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceEventBridge,
		ResourceType: eventBridgeRuleResourceType,
		ResourceID:   resourceID,
		Name:         ruleName,
		ARN:          ruleARN,
		State:        strings.TrimSpace(string(rule.State)),
		Attributes: map[string]any{
			"description":         strings.TrimSpace(aws.ToString(rule.Description)),
			"event_bus_name":      eventBusName,
			"event_pattern":       strings.TrimSpace(aws.ToString(rule.EventPattern)),
			"managed_by":          strings.TrimSpace(aws.ToString(rule.ManagedBy)),
			"role_arn":            strings.TrimSpace(aws.ToString(rule.RoleArn)),
			"schedule_expression": strings.TrimSpace(aws.ToString(rule.ScheduleExpression)),
		},
		CorrelationAnchors: []string{ruleARN, ruleName, netdataJoinNonEmpty("/", eventBusName, ruleName)},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	busID := netdataFirstNonEmpty(busARN, busName, eventBusName)
	if resourceID == "" || busID == "" {
		return row
	}
	row.Relationships = append(row.Relationships, collector.LiveRelationship{
		Region: region, ServiceKind: catalog.ServiceEventBridge,
		RelationshipType: eventBridgeRuleOnEventBusRelationship,
		SourceResourceID: resourceID, SourceARN: ruleARN,
		TargetResourceID: busID, TargetARN: busARN,
		TargetType: eventBridgeEventBusResourceType,
		Attributes: map[string]any{
			"event_bus_name": netdataFirstNonEmpty(eventBusName, busName),
			"rule_name":      ruleName,
		},
		SourceRecordID: resourceID + "->" + busID,
	})
	return row
}

// iamPolicyRecord gives a ListPolicies row its typed home. The translation
// mirrors the in-tree policyObservation field for field, including tags:
// ListPolicies returns them inline, so no extra read is needed. Policy
// documents need a GetPolicyVersion read the listing does not make, so the
// row carries no attachment edge.
func iamPolicyRecord(policy iamtypes.Policy, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(policy.Arn))
	name := strings.TrimSpace(aws.ToString(policy.PolicyName))
	row := record(arn, catalog.ServiceIAM, region, name, "policy")
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceIAM,
		ResourceType: iamPolicyResourceType,
		ResourceID:   arn,
		Name:         name,
		ARN:          arn,
		Tags:         netdataIAMTags(policy.Tags),
		Attributes: map[string]any{
			"attachment_count":   aws.ToInt32(policy.AttachmentCount),
			"default_version_id": strings.TrimSpace(aws.ToString(policy.DefaultVersionId)),
			"path":               strings.TrimSpace(aws.ToString(policy.Path)),
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     arn,
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

// iamInstanceProfileRecord gives a ListInstanceProfiles row its typed home
// plus one role-membership edge per reported role, mirroring the in-tree
// profileRoleRelationship. Tags arrive inline on the list read.
func iamInstanceProfileRecord(profile iamtypes.InstanceProfile, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(profile.Arn))
	name := strings.TrimSpace(aws.ToString(profile.InstanceProfileName))
	row := record(arn, catalog.ServiceIAM, region, name, "instance-profile")
	var roleARNs []string
	for _, role := range profile.Roles {
		if candidate := strings.TrimSpace(aws.ToString(role.Arn)); candidate != "" {
			roleARNs = append(roleARNs, candidate)
		}
	}
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceIAM,
		ResourceType: iamInstanceProfileResourceType,
		ResourceID:   arn,
		Name:         name,
		ARN:          arn,
		Tags:         netdataIAMTags(profile.Tags),
		Attributes: map[string]any{
			"path":      strings.TrimSpace(aws.ToString(profile.Path)),
			"role_arns": roleARNs,
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     arn,
	}
	row.Resource = resource
	row.TypedOnly = true
	for _, roleARN := range roleARNs {
		if arn == "" {
			continue
		}
		row.Relationships = append(row.Relationships, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceIAM,
			RelationshipType: iamRoleInInstanceProfileRelationship,
			SourceResourceID: roleARN, SourceARN: roleARN,
			TargetResourceID: arn, TargetARN: arn,
			TargetType:     iamInstanceProfileResourceType,
			SourceRecordID: roleARN + "#instance-profile#" + arn,
		})
	}
	return row
}

// iamOIDCProviderRecord gives a ListOpenIDConnectProviders row its typed
// home. The in-tree IAM scanner emits OIDC providers as posture principal
// envelopes (iam/secrets_observations.go:53), but the satellite Record has
// no principal slot, so the row is homed as a Resource mirroring the
// eks_oidc.go:134 precedent: provider identity plus the URL fingerprint and
// client/thumbprint counts in Attributes. The listing makes no
// GetOpenIDConnectProvider call, so enrichment rows carry an empty URL and
// zero counts until that read lands.
func iamOIDCProviderRecord(providerARN, url string, clientIDs, thumbprints []string, region string) collector.Record {
	arn := strings.TrimSpace(providerARN)
	name := lastSegment(arn, "/")
	row := record(arn, catalog.ServiceIAM, region, name, "oidc-provider")
	issuer := strings.TrimSpace(url)
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceIAM,
		ResourceType: iamOIDCProviderResourceType,
		ResourceID:   arn,
		Name:         issuer,
		ARN:          arn,
		Attributes: map[string]any{
			"issuer_url":       issuer,
			"url_fingerprint":  normalizeEKSOIDCIssuer(issuer),
			"client_id_count":  len(clientIDs),
			"thumbprint_count": len(thumbprints),
		},
		CorrelationAnchors: []string{arn, issuer},
		SourceRecordID:     arn,
	}
	if resource.Name == "" {
		resource.Name = name
	}
	row.Resource = resource
	row.TypedOnly = true
	return row
}

// dynamoDBTableRecord gives a DescribeTable row its typed home and the KMS
// edge the in-tree tableEnvelopes emits. The translation mirrors the
// in-tree tableObservation fields the describe read returns; stream,
// backup, and export payloads stay unread.
func dynamoDBTableRecord(table dynamodbtypes.TableDescription, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(table.TableArn))
	name := strings.TrimSpace(aws.ToString(table.TableName))
	row := record(arn, catalog.ServiceDynamoDB, region, name, "table")
	resourceID := netdataFirstNonEmpty(arn, strings.TrimSpace(aws.ToString(table.TableId)), name)
	billingMode := ""
	if table.BillingModeSummary != nil {
		billingMode = strings.TrimSpace(string(table.BillingModeSummary.BillingMode))
	}
	sseStatus, sseType, kmsKeyARN := "", "", ""
	if table.SSEDescription != nil {
		sseStatus = strings.TrimSpace(string(table.SSEDescription.Status))
		sseType = strings.TrimSpace(string(table.SSEDescription.SSEType))
		kmsKeyARN = strings.TrimSpace(aws.ToString(table.SSEDescription.KMSMasterKeyArn))
	}
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceDynamoDB,
		ResourceType: dynamoDBTableResourceType,
		ResourceID:   resourceID,
		Name:         name,
		ARN:          arn,
		State:        strings.TrimSpace(string(table.TableStatus)),
		Attributes: map[string]any{
			"table_id":                    strings.TrimSpace(aws.ToString(table.TableId)),
			"creation_time":               netdataTimeOrNil(table.CreationDateTime),
			"billing_mode":                billingMode,
			"sse_status":                  sseStatus,
			"sse_type":                    sseType,
			"kms_master_key_arn":          kmsKeyARN,
			"item_count":                  aws.ToInt64(table.ItemCount),
			"table_size_bytes":            aws.ToInt64(table.TableSizeBytes),
			"deletion_protection_enabled": aws.ToBool(table.DeletionProtectionEnabled),
		},
		CorrelationAnchors: []string{arn, name, strings.TrimSpace(aws.ToString(table.TableId))},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	if resourceID == "" || kmsKeyARN == "" {
		return row
	}
	targetARN := ""
	if strings.HasPrefix(kmsKeyARN, "arn:") {
		targetARN = kmsKeyARN
	}
	row.Relationships = append(row.Relationships, collector.LiveRelationship{
		Region: region, ServiceKind: catalog.ServiceDynamoDB,
		RelationshipType: dynamoDBTableUsesKMSKeyRelationship,
		SourceResourceID: resourceID, SourceARN: arn,
		TargetResourceID: kmsKeyARN, TargetARN: targetARN,
		TargetType:     "aws_kms_key",
		SourceRecordID: resourceID + "->" + dynamoDBTableUsesKMSKeyRelationship + ":" + kmsKeyARN,
	})
	return row
}

// secretsManagerSecretRecord gives a ListSecrets row its typed home plus the
// KMS and rotation-lambda edges the in-tree secretEnvelopes emits. Secret
// values and version payloads stay unread.
func secretsManagerSecretRecord(secret secretstypes.SecretListEntry, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(secret.ARN))
	name := strings.TrimSpace(aws.ToString(secret.Name))
	row := record(arn, catalog.ServiceSecretsManager, region, name, "secret")
	resourceID := netdataFirstNonEmpty(arn, name)
	kmsKeyID := strings.TrimSpace(aws.ToString(secret.KmsKeyId))
	rotationLambdaARN := strings.TrimSpace(aws.ToString(secret.RotationLambdaARN))
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceSecretsManager,
		ResourceType: secretsManagerSecretResourceType,
		ResourceID:   resourceID,
		Name:         name,
		ARN:          arn,
		Attributes: map[string]any{
			"description_present": strings.TrimSpace(aws.ToString(secret.Description)) != "",
			"kms_key_id":          kmsKeyID,
			"rotation_enabled":    aws.ToBool(secret.RotationEnabled),
			"rotation_lambda_arn": rotationLambdaARN,
			"owning_service":      strings.TrimSpace(aws.ToString(secret.OwningService)),
			"primary_region":      strings.TrimSpace(aws.ToString(secret.PrimaryRegion)),
			"created_at":          netdataTimeOrNil(secret.CreatedDate),
			"deleted_at":          netdataTimeOrNil(secret.DeletedDate),
			"last_changed_at":     netdataTimeOrNil(secret.LastChangedDate),
			"last_rotated_at":     netdataTimeOrNil(secret.LastRotatedDate),
			"next_rotation_at":    netdataTimeOrNil(secret.NextRotationDate),
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	if resourceID == "" {
		return row
	}
	if kmsKeyID != "" {
		targetARN := ""
		if strings.HasPrefix(kmsKeyID, "arn:") {
			targetARN = kmsKeyID
		}
		row.Relationships = append(row.Relationships, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceSecretsManager,
			RelationshipType: secretsManagerSecretUsesKMSKeyRelationship,
			SourceResourceID: resourceID, SourceARN: arn,
			TargetResourceID: kmsKeyID, TargetARN: targetARN,
			TargetType:     "aws_kms_key",
			SourceRecordID: resourceID + "->" + secretsManagerSecretUsesKMSKeyRelationship + ":" + kmsKeyID,
		})
	}
	if rotationLambdaARN != "" {
		row.Relationships = append(row.Relationships, collector.LiveRelationship{
			Region: region, ServiceKind: catalog.ServiceSecretsManager,
			RelationshipType: secretsManagerSecretUsesRotationLambdaRelationship,
			SourceResourceID: resourceID, SourceARN: arn,
			TargetResourceID: rotationLambdaARN, TargetARN: rotationLambdaARN,
			TargetType:     catalog.ResourceTypeLambdaFunction,
			SourceRecordID: resourceID + "->" + secretsManagerSecretUsesRotationLambdaRelationship + ":" + rotationLambdaARN,
		})
	}
	return row
}

func netdataFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func netdataJoinNonEmpty(separator string, values ...string) string {
	var kept []string
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, separator)
}

func netdataTimeOrNil(input *time.Time) any {
	if input == nil || input.IsZero() {
		return nil
	}
	return input.UTC()
}

func netdataTimeMillis(milliseconds *int64) any {
	if milliseconds == nil {
		return nil
	}
	return time.UnixMilli(*milliseconds).UTC()
}

func netdataIAMTags(tags []iamtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	output := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := strings.TrimSpace(aws.ToString(tag.Key))
		if key == "" {
			continue
		}
		output[key] = aws.ToString(tag.Value)
	}
	if len(output) == 0 {
		return nil
	}
	return output
}
