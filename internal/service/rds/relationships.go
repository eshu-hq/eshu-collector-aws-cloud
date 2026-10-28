// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package rds

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func securityGroupARN(boundary awscloud.Boundary, groupID string) string {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" || strings.HasPrefix(groupID, "arn:") {
		return groupID
	}
	return "arn:" + awscloud.PartitionForBoundary(boundary) + ":ec2:" + boundary.Region + ":" + boundary.AccountID + ":security-group/" + groupID
}
