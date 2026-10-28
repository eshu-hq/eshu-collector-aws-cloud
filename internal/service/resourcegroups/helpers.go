// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package resourcegroups

import (
	"strings"
	"time"
)

// queryTypeCloudFormationStack is the AWS Resource Groups query type that marks
// a group whose membership is derived from a CloudFormation stack. The scanner
// uses it to decide whether to emit a group-to-stack edge in addition to (or
// instead of) per-member edges.

// arnFields is the parsed view of an AWS ARN split on its colon separators:
// arn:partition:service:region:account:resource. Resource is the remainder
// after the fifth colon and may itself contain "/" or ":" separators, which the
// classifier inspects per service.

// parseARN splits an AWS ARN into its component fields. It returns ok=false when
// the value is not an arn:-prefixed string with at least the six leading
// segments, so the caller can skip a malformed identifier rather than emit a
// dangling edge. The resource segment keeps any internal "/" or ":" because the
// resource-type and resource-id split differs per service.

// SplitN with 6 keeps the resource (which can contain colons) intact.

// resourceTypeAndID splits an ARN resource segment into its leading type token
// and the remaining identifier. AWS uses either "type/id" or "type:id" for the
// segment; the function splits on the first "/" or ":" it sees, whichever comes
// first, so it handles both forms. When the segment has no separator the whole
// segment is the id and the type token is empty (the bare-resource form, for
// example an S3 bucket name).

// memberTarget is the typed join target the classifier resolves for one member
// ARN. ResourceID is the identity the target family's scanner publishes:
// ARNEquality targets carry the full member ARN and set ARN=true so the edge is
// ARN-keyed; bare-id and prefixed-id targets carry the published id form and
// leave ARN=false so the relationship is not falsely marked ARN-keyed.

// Type is a declared awscloud.ResourceType* value (or an allowlisted
// forward-reference target_type) naming the member's resource family.

// ResourceID is the identity the target family's scanner publishes for this
// member, used as the relationship target_resource_id.

// ARNKeyed reports whether the target family is keyed by ARN-equality. When
// true the relationship sets target_arn to the member ARN; when false the
// relationship leaves target_arn empty so the bare/prefixed id is not
// misread as an ARN-keyed join.

// classifyMember maps a Resource Groups member ARN to its resource family and
// the identity that family's scanner publishes. It parses the ARN's colon
// fields exactly (never substring-matches the raw ARN) and returns ok=false for
// any family Eshu does not recognize, so the caller SKIPS the member rather than
// emitting an edge with an empty or guessed target type.
//
// The published identity must match the target scanner exactly or the edge
// dangles: ARN-keyed families (S3, Lambda, DynamoDB, SQS, SNS, Kinesis, RDS,
// ECS, EKS, ELBv2, Secrets Manager, CloudFormation stack) publish the full ARN;
// EC2 instance/VPC/subnet/security-group/network-interface and Elastic IP
// publish the bare id (i-..., vpc-..., eipalloc-..., etc.); KMS keys publish the
// bare key id; Route 53 hosted zones publish the "/hostedzone/<id>" prefixed id.

// arn:p:s3:::bucket-name. The s3 scanner keys the bucket by its ARN.

// arn:p:lambda:region:acct:function:name. The lambda scanner keys the
// function by its ARN.

// SQS queue ARNs have no resource-type token; the resource segment is the
// queue name. The sqs scanner keys the queue by its ARN.

// SNS topic ARNs have no resource-type token; the resource segment is the
// topic name. The sns scanner keys the topic by its ARN.

// arn:p:elasticloadbalancing:region:acct:loadbalancer/app/name/id. The
// elbv2 scanner keys the load balancer by its ARN.

// arn:p:cloudformation:region:acct:stack/name/guid. The cloudformation
// scanner keys the stack by its StackId, which is this ARN.

// arn:p:kms:region:acct:key/<key-id>. The kms scanner keys the key by its
// bare key id, NOT the ARN, so this target is not ARN-keyed.

// arn:p:route53:::hostedzone/<id>. The route53 scanner keys the hosted
// zone by the "/hostedzone/<id>" prefixed id, so reconstruct that form.

// classifyEC2Member resolves the EC2-family resource types Resource Groups can
// report as members. EC2 vpc/subnet/security-group/network-interface/instance
// and Elastic IP are all keyed by their bare id (vpc-..., subnet-..., sg-...,
// eni-..., i-..., eipalloc-...) by their owning scanner, so none of these
// targets is ARN-keyed. Unrecognized EC2 sub-types return ok=false so the caller
// skips them.

// aws_ec2_instance is a documented forward reference: it is keyed by the
// bare instance id (see relguard.KnownTargetTypeAllowlist).

// arnTarget builds an ARN-keyed member target: the relationship target_resource_id
// and target_arn are both the member ARN.

// bareTarget builds a non-ARN-keyed member target whose target_resource_id is
// the bare or prefixed id the target scanner publishes; target_arn is left
// empty so the edge is not falsely marked ARN-keyed.

// firstNonEmpty returns the first trimmed-non-empty value, or "".
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// timeOrNil returns the UTC time for attribute maps, or nil when the time is
// the zero value so the attribute is absent rather than a 0001-01-01 marker.
func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
