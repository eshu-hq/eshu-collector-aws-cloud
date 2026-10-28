// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package transfer

import (
	"strings"
)

// isARN reports whether value is an ARN, matching the isARN helpers the other
// scanner packages use to gate ARN-keyed relationship emission.
func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}

// partition returns the AWS partition for the scan boundary's region — aws,
// aws-cn, or aws-us-gov. Transfer servers and users carry ARNs from the API,
// but home-directory S3 buckets and EFS file systems are reported as bare
// paths, so the boundary region is the partition source for the synthesized
// bucket and file-system ARNs. Hardcoding the commercial partition would dangle
// the user->S3-bucket and user->EFS-file-system edges in GovCloud and China.

// firstPathSegment returns the first non-empty `/`-delimited segment of path
// and the remaining suffix after it. It returns ok=false when path has no
// leading segment. The path is treated as a POSIX-style home directory such as
// `/bucket/key/prefix` or `/fs-0123/path`.

// looksLikeEFSFileSystemID reports whether segment is an EFS file system ID
// (fs-...). AWS Transfer EFS-domain home directories are keyed by the EFS file
// system ID as the leading path segment, so the scanner classifies the backing
// store by this prefix when the server domain is not authoritative.

// EFS file system IDs are fs- followed by 8 (legacy) or 17 hex characters.
// An S3 bucket name can legally start with "fs-", so a bare prefix check
// would misclassify an S3 home directory as EFS; require the hex shape.
