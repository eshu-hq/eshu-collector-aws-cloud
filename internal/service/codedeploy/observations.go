// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package codedeploy

import (
	"fmt"
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// applicationARN builds the canonical CodeDeploy application ARN. The
// CodeDeploy list/batch APIs do not return ARNs, so the scanner derives a
// stable identity from the boundary account and region plus the application
// name, matching the documented AWS ARN format.
func applicationARN(boundary awscloud.Boundary, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:codedeploy:%s:%s:application:%s",
		awscloud.PartitionForBoundary(boundary), boundary.Region, boundary.AccountID, name)
}

// deploymentGroupARN builds the canonical CodeDeploy deployment-group ARN from
// the application and group names.
func deploymentGroupARN(boundary awscloud.Boundary, application, group string) string {
	application = strings.TrimSpace(application)
	group = strings.TrimSpace(group)
	if application == "" || group == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:codedeploy:%s:%s:deploymentgroup:%s/%s",
		awscloud.PartitionForBoundary(boundary), boundary.Region, boundary.AccountID, application, group)
}

// deploymentConfigARN builds the canonical CodeDeploy deployment-config ARN.
func deploymentConfigARN(boundary awscloud.Boundary, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:codedeploy:%s:%s:deploymentconfig:%s",
		awscloud.PartitionForBoundary(boundary), boundary.Region, boundary.AccountID, name)
}

// ecsServiceARN builds the canonical Amazon ECS service ARN for a CodeDeploy
// ECS deployment target. CodeDeploy reports the target as a cluster/service
// name pair, but the ECS scanner emits its service resource_id as this ARN, so
// the relationship must target the same ARN to join the ECS service node.
func ecsServiceARN(boundary awscloud.Boundary, cluster, service string) string {
	cluster = strings.TrimSpace(cluster)
	service = strings.TrimSpace(service)
	if cluster == "" || service == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:ecs:%s:%s:service/%s/%s",
		awscloud.PartitionForBoundary(boundary), boundary.Region, boundary.AccountID, cluster, service)
}

// lambdaFunctionARN builds the canonical AWS Lambda function ARN for a
// CodeDeploy Lambda deployment target. CodeDeploy names the target by function
// name, but the Lambda scanner emits its function resource_id as this ARN, so
// the relationship must target the same ARN to join the function node.
func lambdaFunctionARN(boundary awscloud.Boundary, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:lambda:%s:%s:function:%s",
		awscloud.PartitionForBoundary(boundary), boundary.Region, boundary.AccountID, name)
}

// deploymentARN builds the canonical CodeDeploy deployment ARN from the
// deployment ID.
func deploymentARN(boundary awscloud.Boundary, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:codedeploy:%s:%s:deployment:%s",
		awscloud.PartitionForBoundary(boundary), boundary.Region, boundary.AccountID, id)
}

// tagFilterAttributes maps tag-filter summaries into fact payload maps. The
// value is the redaction marker map when present; raw filter values never
// reach this function.
