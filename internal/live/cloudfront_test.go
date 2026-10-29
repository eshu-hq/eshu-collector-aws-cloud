// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

func TestCloudFrontDistributionEmitsTypedMetadataAndDependencies(t *testing.T) {
	arn := "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHDS5"
	certificate := "arn:aws:acm:us-east-1:123456789012:certificate/cert-1"
	row := cloudFrontDistributionRecord(cloudfronttypes.DistributionSummary{
		ARN: aws.String(arn), Id: aws.String("EDFDVBD632BHDS5"), DomainName: aws.String("d111.cloudfront.net"),
		Status: aws.String("Deployed"), WebACLId: aws.String("classic-web-acl"),
		Origins:           &cloudfronttypes.Origins{Items: []cloudfronttypes.Origin{{CustomHeaders: &cloudfronttypes.CustomHeaders{Items: []cloudfronttypes.OriginCustomHeader{{HeaderName: aws.String("X-Origin-Auth"), HeaderValue: aws.String("private-value")}}}}}},
		ViewerCertificate: &cloudfronttypes.ViewerCertificate{ACMCertificateArn: aws.String(certificate)},
	})
	if row.Resource == nil || row.Resource.Region != "aws-global" || row.Resource.ResourceID != arn || row.Resource.Name != "EDFDVBD632BHDS5" || len(row.Relationships) != 2 {
		t.Fatalf("typed distribution = %#v", row)
	}
	if row.Relationships[0].TargetARN != certificate || row.Relationships[1].TargetResourceID != "classic-web-acl" || row.Relationships[1].TargetARN != "" {
		t.Fatalf("dependency edges = %#v", row.Relationships)
	}
	wire, err := json.Marshal(row.Resource.Attributes)
	if err != nil || strings.Contains(string(wire), "private-value") || !strings.Contains(string(wire), "X-Origin-Auth") {
		t.Fatalf("redacted origin metadata = %s, err=%v", wire, err)
	}
}
