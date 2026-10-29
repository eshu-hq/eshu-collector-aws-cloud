// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSensitiveReadErrorPreservesSafeContextSentinels(t *testing.T) {
	const canary = "raw-sdk-error-canary"
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		wrapped := fmt.Errorf("%s: %w", canary, sentinel)
		got := sensitiveReadError("lambda get function", wrapped)
		if !errors.Is(got, sentinel) || strings.Contains(got.Error(), canary) {
			t.Fatalf("context sentinel or redaction lost: error=%v sentinel=%v", got, sentinel)
		}
	}
}
