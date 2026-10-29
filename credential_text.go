// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import "strings"

// credentialValueMarkers are substrings that mark free text as unsafe to
// emit. Matching is deliberately broad: a withheld reason stays diagnosable
// through its redaction record, while a leaked credential does not.
//
// The AMI name hygiene scan (internal/live/ec2_ami_name.go) reuses this list
// as a drop trigger under eshu-hq/eshu#9525. Additions here widen both the
// redaction path and that scan; removals narrow both. Neither caller may carry
// a private copy of this list.
var credentialValueMarkers = []string{
	"password", "passwd", "secret", "token", "bearer",
	"api_key", "apikey", "private_key", "client_secret", "credentials",
}

// ContainsCredentialText reports whether free text may carry a credential, per
// the shared satellite-local marker list. It is a drop/withhold trigger only:
// callers never emit, narrow, or log what matched.
func ContainsCredentialText(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range credentialValueMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
