// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func TestECSServiceTaskDefinitionRelationshipMatchesLegacy(t *testing.T) {
	serviceARN := "arn:aws:ecs:us-east-1:123456789012:service/prod/web"
	definitionARN := "arn:aws:ecs:us-east-1:123456789012:task-definition/web:4"
	row := mustECSServiceRecord(t, awsecstypes.Service{ServiceArn: aws.String(serviceARN), TaskDefinition: aws.String(" " + definitionARN + " ")}, "us-east-1")
	if row.Relationship == nil {
		t.Fatal("service task definition relationship missing")
	}
	edge := *row.Relationship
	if edge.RelationshipType != catalog.RelationshipECSServiceUsesTaskDefinition || edge.SourceResourceID != serviceARN || edge.SourceARN != serviceARN || edge.TargetResourceID != definitionARN || edge.TargetARN != definitionARN || edge.TargetType != catalog.ResourceTypeECSTaskDefinition || edge.SourceRecordID != serviceARN+"#task-definition#"+definitionARN {
		t.Fatalf("service task definition relationship changed: %+v", edge)
	}
	observed := relationshipObservation("123456789012", edge)
	if observed.Boundary.AccountID != "123456789012" || observed.Boundary.Region != "us-east-1" || observed.Boundary.ServiceKind != "ecs" {
		t.Fatalf("relationship lost claim binding: %+v", observed.Boundary)
	}
}

func TestECSServiceTaskDefinitionRelationshipRequiresBothARNs(t *testing.T) {
	for _, service := range []awsecstypes.Service{
		{ServiceArn: aws.String("arn:aws:ecs:us-east-1:123456789012:service/prod/web")},
		{TaskDefinition: aws.String("arn:aws:ecs:us-east-1:123456789012:task-definition/web:4")},
	} {
		if row := mustECSServiceRecord(t, service, "us-east-1"); row.Relationship != nil {
			t.Fatalf("invented relationship: %+v", row.Relationship)
		}
	}
}

func TestECSTaskNetworkInterfaceRelationshipMatchesLegacy(t *testing.T) {
	taskARN := "arn:aws:ecs:us-east-1:123456789012:task/prod/abc"
	task := awsecstypes.Task{
		TaskArn: aws.String(taskARN), TaskDefinitionArn: aws.String("definition-arn"),
		Attachments: []awsecstypes.Attachment{{Type: aws.String("ElasticNetworkInterface"), Details: []awsecstypes.KeyValuePair{{Name: aws.String("networkInterfaceId"), Value: aws.String("eni-123")}, {Name: aws.String("subnetId"), Value: aws.String("subnet-123")}}}},
	}
	row := ecsTaskRecord(task, "us-east-1")
	if len(row.Relationships) != 1 {
		t.Fatalf("task ENI relationship missing: %+v", row.Relationships)
	}
	edge := row.Relationships[0]
	if edge.RelationshipType != catalog.RelationshipECSTaskUsesNetworkInterface || edge.SourceResourceID != taskARN || edge.SourceARN != taskARN || edge.TargetResourceID != "eni-123" || edge.TargetARN != "" || edge.TargetType != catalog.ResourceTypeEC2NetworkInterface || edge.SourceRecordID != taskARN+"#network-interface#eni-123" || edge.Attributes["subnet_id"] != "subnet-123" {
		t.Fatalf("task ENI relationship changed: %+v", edge)
	}
	observed := relationshipObservation("123456789012", edge)
	if observed.Boundary.AccountID != "123456789012" || observed.Boundary.Region != "us-east-1" || observed.Boundary.ServiceKind != "ecs" {
		t.Fatalf("task ENI relationship lost claim binding: %+v", observed.Boundary)
	}
}

func TestECSTaskNetworkInterfaceRelationshipNeedsReportedENIID(t *testing.T) {
	row := ecsTaskRecord(awsecstypes.Task{TaskArn: aws.String("arn:aws:ecs:us-east-1:123456789012:task/prod/abc"), Attachments: []awsecstypes.Attachment{{Type: aws.String("ElasticNetworkInterface")}}}, "us-east-1")
	if len(row.Relationships) != 0 {
		t.Fatalf("invented ENI relationship: %+v", row.Relationships)
	}
}
