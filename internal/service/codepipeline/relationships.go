// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package codepipeline

// ResourceTypeCodePipelineSourceProvider names the synthetic provider category
// a source-action edge points at. A source action's concrete repository or
// bucket lives in action configuration values the scanner never persists, so
// the edge documents the provider class (S3, CodeCommit, GitHub,
// CodeStarSourceConnection, Bitbucket) only and never carries an empty
// target_type.
const ResourceTypeCodePipelineSourceProvider = "aws_codepipeline_source_provider"

// pipelineRelationships derives every relationship a pipeline reports: the
// service role, the S3 artifact store, the KMS encryption key, stage->action
// containment, action->source-provider edges, and action->target edges for the
// build/deploy/invoke targets resolved from allowlisted non-secret
// configuration keys.

// CodePipeline reports the encryption key as a bare key id, a key ARN, or an
// alias ARN. The KMS scanner emits a key node (resource_id = bare key id or
// key ARN, anchors [keyARN, keyID]) and a separate alias node (resource_id =
// alias ARN or alias name, anchors [aliasARN, aliasName]). A KMS key never
// carries an alias ARN in its anchors, so an alias-ARN reference must target
// the alias node, not the key node, or the edge dangles. Detect the alias-ARN
// shape (:alias/) and target aws_kms_alias for those; keep aws_kms_key for
// key ARNs and bare key ids. Set target_arn only when the value is an ARN.

// actionTargetRelationship resolves the build/deploy/invoke target edge from
// the allowlisted non-secret target identifier the adapter read. It joins the
// target scanner's node by matching that scanner's resource_id, never an empty
// target_type. The target name came from a known identifier configuration key
// (ProjectName, ApplicationName, FunctionName, StackName, ClusterName +
// ServiceName), never from a secret configuration value.

// The CloudFormation scanner's stack node carries the stack name in its
// correlation anchors. CodePipeline reports only the stack name (the
// real stack id ARN has an account-generated UUID suffix this scanner
// cannot know), so target the stack name to join the stack node by its
// name anchor; leave target_arn empty rather than emit a wrong ARN.

// s3BucketARN builds the S3 bucket ARN. The S3 scanner emits its bucket
// resource_id as the bucket ARN, so the artifact-store edge targets that ARN.

// ecsServiceARN builds the Amazon ECS service ARN. The ECS scanner emits its
// service resource_id as this ARN, so the deploy-action edge targets the same
// ARN to join the ECS service node. CodePipeline reports the target as a
// cluster/service pair, never a bare service name.
