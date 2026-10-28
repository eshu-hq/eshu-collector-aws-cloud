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
