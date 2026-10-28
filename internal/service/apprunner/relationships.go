// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package apprunner

import (
	"strings"
)

// serviceRelationships records the image, connection, IAM-role, KMS-key,
// VPC-connector, autoscaling, observability, and secret-reference joins of one
// App Runner service. Every edge sets a non-empty target_type matching the
// target scanner's resource_id form, and the source resource_id is the service
// ARN so it matches the ACM/WAFv2 edge target join key.

// vpcConnectorRelationships records the subnet and security-group joins of one
// App Runner VPC connector. Subnets and security groups key on the bare AWS IDs
// so the EC2-owned subnet/security-group resources resolve.

// vpcIngressConnectionRelationships records the service a VPC ingress
// connection routes inbound traffic to. The target keys on the service ARN.

// secretReferenceTargetType classifies a runtime secret reference ARN as an SSM
// parameter when the ARN names the ssm service, otherwise as a Secrets Manager
// secret.

// arnOrEmpty returns the candidate when it is an ARN, so relationship target
// ARNs stay accurate for non-ARN identities.
func arnOrEmpty(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if strings.HasPrefix(candidate, "arn:") {
		return candidate
	}
	return ""
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		output = append(output, value)
	}
	return output
}
