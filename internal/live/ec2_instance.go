// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// instanceRecord retains the identity observation reported by the legacy EC2
// scanner from DescribeInstances. Instance posture is a separate fact kind.
func instanceRecord(instance ec2types.Instance, region string, identity VerifiedIdentity) collector.Record {
	id := strings.TrimSpace(aws.ToString(instance.InstanceId))
	result := record(id, "ec2", region, ec2Name(instance.Tags, id), "instance")
	if result.Resource == nil {
		return result
	}
	resource := result.Resource
	resource.ARN = "arn:" + identity.Partition + ":ec2:" + region + ":" + identity.AccountID + ":instance/" + id
	if instance.State != nil {
		resource.State = strings.TrimSpace(string(instance.State.Name))
	}
	resource.Attributes = map[string]any{"ami_id": strings.TrimSpace(aws.ToString(instance.ImageId))}
	return result
}
