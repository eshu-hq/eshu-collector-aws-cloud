// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/smithy-go"
)

// sensitiveReadError keeps useful AWS failure classes without forwarding an
// SDK error message that could contain response data from a sensitive read.
// Cancellation and deadline errors wrap only their safe context sentinels.
func sensitiveReadError(operation string, err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", operation, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", operation, context.DeadlineExceeded)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch code := apiErr.ErrorCode(); code {
		case "AccessDeniedException", "ClientException", "InternalFailure",
			"InternalServiceException", "InvalidParameterException",
			"InvalidParameterValueException", "ResourceNotFoundException",
			"ServerException", "ServiceException", "ThrottlingException",
			"TooManyRequestsException":
			return fmt.Errorf("%s: %s", operation, code)
		}
	}
	return fmt.Errorf("%s failed", operation)
}
