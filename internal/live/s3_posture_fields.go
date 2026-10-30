// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// applyS3KnownPosture maps only fields established by successful bucket reads.
// The versioning map also carries the public-access-block flags; an absent
// configuration leaves them unknown rather than four false flags, mirroring
// the in-tree posture observation.
func applyS3KnownPosture(out *collector.S3BucketPostureObservation, versioning, ownership, logging map[string]any, loggingObserved bool) {
	out.BlockPublicACLs = s3PostureFlag(versioning["block_public_acls"])
	out.IgnorePublicACLs = s3PostureFlag(versioning["ignore_public_acls"])
	out.BlockPublicPolicy = s3PostureFlag(versioning["block_public_policy"])
	out.RestrictPublicBuckets = s3PostureFlag(versioning["restrict_public_buckets"])
	out.BlockPublicAccessAllEnabled = s3BlockPublicAccessAll(
		out.BlockPublicACLs, out.IgnorePublicACLs, out.BlockPublicPolicy, out.RestrictPublicBuckets,
	)
	if status, ok := versioning["versioning_status"].(string); ok && strings.TrimSpace(status) != "" {
		status = strings.TrimSpace(status)
		out.VersioningStatus = &status
		enabled := strings.EqualFold(status, "Enabled")
		out.VersioningEnabled = &enabled
	}
	if status, ok := versioning["mfa_delete"].(string); ok && strings.TrimSpace(status) != "" {
		enabled := strings.EqualFold(strings.TrimSpace(status), "Enabled")
		out.MFADeleteEnabled = &enabled
	}
	if controls, ok := ownership["ownership_controls"].([]string); ok && len(controls) > 0 {
		out.ObjectOwnership = append([]string(nil), controls...)
		disabled := false
		for _, control := range controls {
			if strings.EqualFold(strings.TrimSpace(control), "BucketOwnerEnforced") {
				disabled = true
				break
			}
		}
		out.ACLDisabled = &disabled
	}
	if loggingObserved {
		if enabled, ok := logging["logging_enabled"].(bool); ok {
			out.LoggingEnabled = &enabled
			if enabled {
				if target, ok := logging["logging_target_bucket"].(string); ok {
					out.LoggingTargetBucket = strings.TrimSpace(target)
				}
			}
		}
	}
}

// s3PostureFlag keeps the unknown state of an absent public-access-block flag.
// Only a confirmed boolean becomes a posture value; anything else stays nil.
func s3PostureFlag(value any) *bool {
	enabled, ok := value.(bool)
	if !ok {
		return nil
	}
	return &enabled
}

// s3BlockPublicAccessAll reports whether all four block-public-access flags
// are explicitly enabled. It returns nil when any flag is absent so an
// unconfigured bucket stays distinct from one with all four disabled,
// mirroring the in-tree derivation verbatim.
func s3BlockPublicAccessAll(flags ...*bool) *bool {
	all := true
	for _, flag := range flags {
		if flag == nil {
			return nil
		}
		all = all && *flag
	}
	return &all
}

// applyS3EncryptionPosture preserves unknown when the encryption read yielded
// no confirmed configuration. An explicit missing configuration supplies a
// present empty attributes map and therefore a known false enabled state.
func applyS3EncryptionPosture(out *collector.S3BucketPostureObservation, encryption map[string]any) {
	if encryption == nil {
		return
	}
	algorithms, ok := encryption["default_encryption_algorithms"].([]string)
	if !ok {
		return
	}
	out.EncryptionAlgorithms = append([]string(nil), algorithms...)
	enabled := len(algorithms) > 0
	out.DefaultEncryptionEnabled = &enabled
	if keys, ok := encryption["kms_master_key_ids"].([]string); ok && len(keys) > 0 {
		out.SSEKMSKeyARN = strings.TrimSpace(keys[0])
	}
	if bucketKey, ok := encryption["bucket_key_enabled"].(bool); ok {
		out.BucketKeyEnabled = &bucketKey
	}
}
