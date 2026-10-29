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
	row := ecsServiceRecord(awsecstypes.Service{ServiceArn: aws.String(serviceARN), TaskDefinition: aws.String(" " + definitionARN + " ")}, "us-east-1")
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
		if row := ecsServiceRecord(service, "us-east-1"); row.Relationship != nil {
			t.Fatalf("invented relationship: %+v", row.Relationship)
		}
	}
}

func TestECSServiceLoadBalancerRelationshipsMatchLegacy(t *testing.T) {
	serviceARN := "arn:aws:ecs:us-east-1:123456789012:service/prod/web"
	targetARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/abc"
	row := ecsServiceRecord(awsecstypes.Service{
		ServiceArn: aws.String(serviceARN),
		LoadBalancers: []awsecstypes.LoadBalancer{
			{TargetGroupArn: aws.String(" " + targetARN + " "), LoadBalancerName: aws.String("ignored"), ContainerName: aws.String(" web "), ContainerPort: aws.Int32(8080)},
			{LoadBalancerName: aws.String(" classic "), ContainerName: aws.String("api"), ContainerPort: aws.Int32(80)},
		},
	}, "us-east-1")
	if len(row.Relationships) != 2 {
		t.Fatalf("load balancer relationships = %+v, want two", row.Relationships)
	}
	for i, want := range []struct{ id, arn, kind, record string }{
		{targetARN, targetARN, "aws_elbv2_target_group", serviceARN + "#load-balancer#" + targetARN},
		{"classic", "", "aws_elb_load_balancer", serviceARN + "#load-balancer#classic"},
	} {
		edge := row.Relationships[i]
		if edge.RelationshipType != catalog.RelationshipECSServiceTargetsLoadBalancer || edge.SourceResourceID != serviceARN || edge.SourceARN != serviceARN || edge.TargetResourceID != want.id || edge.TargetARN != want.arn || edge.TargetType != want.kind || edge.SourceRecordID != want.record || edge.Region != "us-east-1" || edge.ServiceKind != "ecs" {
			t.Fatalf("load balancer relationship %d changed: %+v", i, edge)
		}
		if edge.Attributes["container_port"] != []int32{8080, 80}[i] || edge.Attributes["container_name"] != []string{"web", "api"}[i] {
			t.Fatalf("load balancer attributes %d changed: %+v", i, edge.Attributes)
		}
		observed := relationshipObservation("123456789012", edge)
		if observed.Boundary.AccountID != "123456789012" || observed.Boundary.Region != "us-east-1" || observed.Boundary.ServiceKind != "ecs" {
			t.Fatalf("relationship lost claim binding: %+v", observed.Boundary)
		}
	}
}

func TestECSServiceLoadBalancerRelationshipsNeedReportedTarget(t *testing.T) {
	row := ecsServiceRecord(awsecstypes.Service{
		ServiceArn:    aws.String("arn:aws:ecs:us-east-1:123456789012:service/prod/web"),
		LoadBalancers: []awsecstypes.LoadBalancer{{ContainerName: aws.String("web"), ContainerPort: aws.Int32(80)}},
	}, "us-east-1")
	if len(row.Relationships) != 0 {
		t.Fatalf("invented load balancer relationship: %+v", row.Relationships)
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
