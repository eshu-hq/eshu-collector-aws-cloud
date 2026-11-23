// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"errors"
	"strings"

	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// loaderFailedObservation builds the typed warning for one ordinary
// service-loader failure (eshu-hq/eshu#11283). The message is a fixed
// template over the bounded error class; attributes carry the operation,
// resource, and effect identity the warning seam requires plus the raw
// smithy error code only, never message text or AWS identities.
func loaderFailedObservation(service, region string, err error) collector.WarningObservation {
	class, code := loaderErrorClass(err)
	return collector.WarningObservation{
		Boundary:    collector.Boundary{Region: region, ServiceKind: service},
		WarningKind: "loader_failed", ErrorClass: class,
		Message:        service + "/" + region + " loader failed (" + class + ")",
		SourceRecordID: service + ":" + region,
		Attributes: map[string]any{
			"operation": "Load", "resource": "region:" + region,
			"effect": "loader-failed", "error_code": code,
		},
	}
}

// loaderErrorClass bounds any loader failure to one reviewed error class
// from the smithy API code, defaulting to loader_error. Non-API failures
// (transports, plain errors, empty codes) stay loader_error with an
// unknown code.
func loaderErrorClass(err error) (class, code string) {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return "loader_error", "unknown"
	}
	code = strings.TrimSpace(apiErr.ErrorCode())
	if code == "" {
		return "loader_error", "unknown"
	}
	switch {
	case isAccessDeniedCode(code):
		return "access_denied", code
	case isThrottlingCode(code):
		return "throttled", code
	case isNotFoundCode(code):
		return "not_found", code
	case isTimeoutCode(code):
		return "network_timeout", code
	default:
		return "loader_error", code
	}
}

// isAccessDeniedCode recognizes the reviewed authorization-failure codes.
func isAccessDeniedCode(code string) bool {
	switch code {
	case "AccessDenied", "AccessDeniedException", "AccessDeniedFault",
		"Unauthorized", "UnauthorizedException", "UnauthorizedOperation",
		"NotAuthorized", "Forbidden", "ForbiddenException":
		return true
	default:
		return false
	}
}

// isThrottlingCode recognizes the reviewed rate-limit codes.
func isThrottlingCode(code string) bool {
	switch code {
	case "Throttling", "ThrottlingException", "Throttled", "ThrottledException",
		"TooManyRequestsException", "RequestThrottled", "RequestThrottledException",
		"RequestLimitExceeded", "SlowDown", "PriorRequestNotComplete":
		return true
	default:
		return false
	}
}

// isNotFoundCode recognizes the reviewed missing-resource shapes: the
// NotFound suffix family and the NoSuch prefix family.
func isNotFoundCode(code string) bool {
	return strings.HasSuffix(code, "NotFound") ||
		strings.HasSuffix(code, "NotFoundException") ||
		strings.HasPrefix(code, "NoSuch")
}

// isTimeoutCode recognizes the reviewed deadline shapes.
func isTimeoutCode(code string) bool {
	switch code {
	case "RequestTimeout", "RequestTimeoutException", "GatewayTimeout", "TimeoutError":
		return true
	default:
		return false
	}
}
