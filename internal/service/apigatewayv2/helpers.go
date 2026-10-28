// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package apigatewayv2

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// stageResourceID keys a stage by its API id and stage name so two APIs cannot
// collide on a shared stage name.

// routeResourceID keys a route by its API id and route id.

// integrationResourceID keys an integration by its API id and integration id.

// authorizerResourceID keys an authorizer by its API id and authorizer id.

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

// isARN reports whether value looks like an AWS ARN.

// integrationTargetFromRoute extracts the integration id a route target
// references. API Gateway v2 reports route targets as "integrations/<id>".

// lambdaARNFromIntegrationURI extracts the Lambda function ARN an AWS_PROXY
// integration invokes. v2 HTTP APIs report the bare function ARN directly; v2
// WebSocket and legacy shapes use the apigateway path form
// "arn:aws:apigateway:<region>:lambda:path/.../functions/<lambdaArn>/invocations".
// It returns "" when the URI is not a Lambda invocation target.

// Bare Lambda function ARN.

// httpEndpointFromIntegrationURI returns the external HTTP(S) endpoint an
// HTTP_PROXY integration forwards to, or "" when the URI is not an HTTP URL.

// userPoolIDFromIssuer extracts the bare Cognito user pool id from a JWT issuer
// URL of the form "https://cognito-idp.<region>.amazonaws.com/<poolId>". It
// returns "" for non-Cognito issuers so a generic OIDC issuer does not dangle as
// a Cognito user pool join. The bare pool id is the resource_id the Cognito
// scanner publishes for the user pool node.

// A Cognito user pool id has the shape "<region>_<suffix>"; reject empty or
// further-pathed values so only the bare pool id becomes a join key.
