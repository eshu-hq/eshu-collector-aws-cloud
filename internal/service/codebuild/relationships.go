// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package codebuild

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// repositorySourceTargetType labels a Git source-provider relationship target.
// The repository is an external (non-AWS-resource) endpoint, so it carries a
// stable non-empty target type without claiming a scanned AWS resource node,
// mirroring how the Lambda scanner labels container-image targets.

// projectSourceTypeS3 is the CodeBuild source type that stores input in S3.

// environmentVariableTypeSecretsManager and environmentVariableTypeParameterStore
// are the CodeBuild environment-variable types whose Value names a Secrets
// Manager secret or an SSM Parameter Store parameter rather than a literal
// value.

// projectRelationships derives the relationship observations CodeBuild reports
// directly for one build project: service role, VPC/subnet/security-group,
// KMS key, S3 or Git source, S3 artifacts, and Secrets Manager / SSM Parameter
// Store environment-variable references. Each edge names a concrete target with
// a non-empty target type so the graph join resolves the target node.

// The KMS scanner emits its key resource_id as firstNonEmpty(keyID, keyARN),
// so a key ARN joins the key node directly and a bare key id or alias joins
// when the project reports that form. CodeBuild reports either an ARN or an
// alias/ prefixed value; both are passed through unchanged.

// sourceRelationship maps one CodeBuild source into a relationship. An S3
// source joins the S3 bucket node by bucket ARN. A Git provider source
// (GitHub, GitHub Enterprise, CodeCommit, Bitbucket, GitLab) joins an external
// repository target labeled with a stable non-AWS-resource target type. A
// CODEPIPELINE or NO_SOURCE source names no concrete resource and is skipped.

// artifactRelationship maps one CodeBuild artifact configuration into an S3
// relationship. Only S3 artifacts name a concrete bucket; NO_ARTIFACTS and
// CODEPIPELINE artifact types are skipped.

// environmentReferenceRelationships derives Secrets Manager and SSM Parameter
// Store relationships from environment variables. SECRETS_MANAGER variables
// reference a secret ARN or name; PARAMETER_STORE variables reference a
// parameter name. Both target the resource_id the owning scanner emits, which
// is firstNonEmpty(ARN, name). PLAINTEXT variables name no resource and are
// excluded here.

// s3BucketARNFromLocation derives the S3 bucket ARN from a CodeBuild S3 source
// or artifact location of the form "bucket-name/path/prefix". It matches the S3
// scanner identity, which emits the bucket ARN as its resource_id, so the edge
// joins the bucket node. When the location is a bare bucket/path, the partition
// is derived from the scan boundary's region; when it is already an S3 ARN, the
// source ARN's partition is preserved. A hardcoded commercial partition would
// dangle the project->S3 edge in GovCloud and China.
func s3BucketARNFromLocation(boundary awscloud.Boundary, location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	if strings.HasPrefix(location, "arn:") {
		// Already an ARN; reduce to the bucket ARN to match the S3 scanner.
		return bucketARNFromObjectARN(location)
	}
	bucket := location
	if slash := strings.IndexByte(location, '/'); slash >= 0 {
		bucket = location[:slash]
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return ""
	}
	return "arn:" + awscloud.PartitionForBoundary(boundary) + ":s3:::" + bucket
}

// bucketARNFromObjectARN trims an S3 object ARN down to the bucket ARN so the
// edge joins the S3 bucket node rather than a non-existent object node. It
// preserves the source ARN's partition (aws / aws-cn / aws-us-gov) by matching
// the partition-agnostic `:s3:::` segment rather than only the commercial
// `arn:aws:s3:::` prefix, so a GovCloud or China object ARN still reduces to the
// correct bucket node instead of being passed through whole.
func bucketARNFromObjectARN(arn string) string {
	const marker = ":s3:::"
	trimmed := strings.TrimSpace(arn)
	if !strings.HasPrefix(trimmed, "arn:") {
		return trimmed
	}
	idx := strings.Index(trimmed, marker)
	if idx < 0 {
		return trimmed
	}
	prefix := trimmed[:idx+len(marker)]
	rest := trimmed[idx+len(marker):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return trimmed
	}
	return prefix + rest
}

// secretARNOrEmpty returns the reference as a target ARN only when CodeBuild
// reported a full Secrets Manager ARN. A bare secret name is still a valid join
// key against the Secrets Manager scanner resource_id, but it is not an ARN.

// ssmParameterARNOrEmpty returns the reference as a target ARN only when
// CodeBuild reported a full SSM parameter ARN. A bare parameter name is still a
// valid join key against the SSM scanner resource_id, but it is not an ARN.
