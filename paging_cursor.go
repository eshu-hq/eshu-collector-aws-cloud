// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// pageCursor is the decoded continuation token: everything a stateless
// resumed process needs to serve its page. The digest binds the cursor to
// the exact fact stream the first page split, so source drift between
// calls fails closed instead of emitting a page the host rejects
// mid-stream. PageSizes pins the page-zero split as fact counts per page
// in order: the resume slices the re-collected set at these boundaries
// instead of re-splitting, so per-call wire-length drift (fresh
// ObservedAt stamps marshal to different byte lengths) cannot regroup
// pages mid-walk and tear the host reassembly (eshu-hq/eshu#11085
// class 1). Counts always partition the admitted set, so a pinned walk
// reassembles exactly the declared total by construction.
type pageCursor struct {
	Version         int    `json:"v"`
	NextPage        int    `json:"next"`
	TotalFacts      int    `json:"total"`
	GenerationID    string `json:"gen"`
	ObservedAtNanos int64  `json:"obs"`
	FreshnessHint   string `json:"fresh,omitempty"`
	TrustedDeletion bool   `json:"td,omitempty"`
	Digest          string `json:"digest"`
	PageSizes       []int  `json:"sizes"`
	// Snapshot binds the cursor to one collect-once walk snapshot: the
	// content digest of the committed fact stream. PageBound pins the
	// per-page byte bound page zero split with (the stored boundary a
	// resume serves), and InstanceID locates the snapshot file. All
	// three ride inside the host-opaque token, so no wire shape changes.
	// Cursors minted before collect-once carry none of them; the
	// snapshot resume path fails those closed instead of resuming at an
	// unbound offset.
	Snapshot   string `json:"snap,omitempty"`
	PageBound  int64  `json:"bound,omitempty"`
	InstanceID string `json:"inst,omitempty"`
}

// encodePageCursor renders one resume token for JSON transport: base64url
// of the compact JSON cursor, so the token carries no padding or escaping
// hazards in the host request document.
func encodePageCursor(cursor pageCursor) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode page cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// decodePageCursor validates one resume token: well-formed encoding, known
// version, sane resume position, and a pinned generation identity. Anything
// else fails closed instead of resuming at an untrusted offset.
func decodePageCursor(encoded string) (pageCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) == 0 {
		return pageCursor{}, fmt.Errorf("decode page cursor: invalid encoding")
	}
	var cursor pageCursor
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&cursor); err != nil {
		return pageCursor{}, fmt.Errorf("decode page cursor: %w", err)
	}
	if cursor.Version != pageCursorVersion {
		return pageCursor{}, fmt.Errorf("decode page cursor: version %d is unsupported", cursor.Version)
	}
	if cursor.NextPage < 0 || cursor.TotalFacts < 0 {
		return pageCursor{}, fmt.Errorf("decode page cursor: negative resume position")
	}
	if strings.TrimSpace(cursor.GenerationID) == "" {
		return pageCursor{}, fmt.Errorf("decode page cursor: generation is required")
	}
	if strings.TrimSpace(cursor.Digest) == "" {
		return pageCursor{}, fmt.Errorf("decode page cursor: digest is required")
	}
	return cursor, nil
}
