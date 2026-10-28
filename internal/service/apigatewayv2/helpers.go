// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package apigatewayv2

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// apiARN synthesizes the API Gateway v2 API ARN from the region and API id. The
// partition is derived from the region (mirroring the v1 API Gateway sibling),
// and the API id is the bare control-plane id, so the synthesized ARN never
// hardcodes an account or a commercial partition.
func apiARN(region, apiID string) string {
	apiID = strings.TrimSpace(apiID)
	if apiID == "" {
		return ""
	}
	region = strings.TrimSpace(region)
	return "arn:" + awscloud.PartitionForRegion(region) + ":apigateway:" + region + "::/apis/" + apiID
}
