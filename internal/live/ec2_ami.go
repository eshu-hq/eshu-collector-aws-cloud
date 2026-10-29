// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// maxAMIImagesPerScan bounds one regional EC2 scan's DescribeImages lookup to
// a single batched call. A scan that references more distinct AMI ids keeps
// the first ids in sorted order and warns with the dropped count.
const maxAMIImagesPerScan = 100

// amiImageDetail is the scanner-owned projection of the EC2 Image fields the
// #9301 contract admits. It carries no name or description field by
// construction: creator-controlled free text never enters the producer
// (see eshu-hq/eshu#9525).
type amiImageDetail struct {
	imageID         string
	platformDetails string
	platform        string
	architecture    string
	creationDate    string
	deprecationTime string
	ownerAlias      string
	rootDeviceType  string
}

// attributes returns the admitted typed attribute map. Absent and blank
// values stay omitted; unparseable timestamps are dropped, never synthesized.
func (detail amiImageDetail) attributes() map[string]any {
	attrs := map[string]any{}
	if value := strings.TrimSpace(detail.platformDetails); value != "" {
		attrs["platform_details"] = value
	}
	if value := strings.TrimSpace(detail.platform); value != "" {
		attrs["platform"] = value
	}
	if value := strings.TrimSpace(detail.architecture); value != "" {
		attrs["architecture"] = value
	}
	if value := strings.TrimSpace(detail.creationDate); value != "" && validAMITimestamp(value) {
		attrs["creation_date"] = value
	}
	if value := strings.TrimSpace(detail.deprecationTime); value != "" && validAMITimestamp(value) {
		attrs["deprecation_time"] = value
	}
	if value := strings.TrimSpace(detail.ownerAlias); value != "" {
		attrs["owner_alias"] = value
	}
	if value := strings.TrimSpace(detail.rootDeviceType); value != "" {
		attrs["root_device_type"] = value
	}
	return attrs
}

// validAMITimestamp reports whether AWS reported an ISO 8601 timestamp.
func validAMITimestamp(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

// amiDetailFromImage projects one SDK image onto the admitted typed fields.
// The image Name and Description are deliberately never read.
func amiDetailFromImage(image ec2types.Image) amiImageDetail {
	return amiImageDetail{
		imageID:         strings.TrimSpace(aws.ToString(image.ImageId)),
		platformDetails: aws.ToString(image.PlatformDetails),
		platform:        string(image.Platform),
		architecture:    string(image.Architecture),
		creationDate:    aws.ToString(image.CreationDate),
		deprecationTime: aws.ToString(image.DeprecationTime),
		ownerAlias:      aws.ToString(image.ImageOwnerAlias),
		rootDeviceType:  string(image.RootDeviceType),
	}
}

// appendAMIDetails resolves the scan's deduplicated AMI ids through one
// bounded DescribeImages call and stamps the admitted typed fields onto the
// matching AMI records. Identity records and the instance relationship survive
// every degradation path: a denial degrades to one warning, a truncated set
// warns with the dropped count, and images the call cannot see warn as
// unresolved without inferring an OS version or a reason. A non-denial
// transport failure stays fatal.
func appendAMIDetails(ctx context.Context, client *awsec2.Client, region string, records []collector.Record, amiIDs map[string]struct{}) (*optionalReadDenied, error) {
	ids := make([]string, 0, len(amiIDs))
	for id := range amiIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			ids = append(ids, trimmed)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	sort.Strings(ids)
	var denials []optionalDenial
	if len(ids) > maxAMIImagesPerScan {
		dropped := len(ids) - maxAMIImagesPerScan
		ids = ids[:maxAMIImagesPerScan]
		denials = append(denials, optionalDenial{
			operation: "DescribeImages",
			resource:  "region:" + region,
			effect:    "ami-details-cap-truncated",
			message: fmt.Sprintf("DescribeImages truncated to %d AMI image(s) for region:%s; ami-details-cap-truncated",
				maxAMIImagesPerScan, region),
			attributes: map[string]any{"dropped_count": dropped},
		})
	}
	// Deprecated AMIs stay included: hosts routinely run on them, and without
	// this flag a deprecated image would read back as unresolved.
	output, err := client.DescribeImages(ctx, &awsec2.DescribeImagesInput{
		ImageIds:          ids,
		IncludeDeprecated: aws.Bool(true),
	})
	if err != nil {
		if isAMIDescribeDenial(err) {
			denials = append(denials, optionalDenial{
				operation: "DescribeImages",
				resource:  "region:" + region,
				effect:    "ami-details-unavailable",
			})
			return &optionalReadDenied{denials: denials}, nil
		}
		return nil, fmt.Errorf("ec2 describe images: %w", err)
	}
	byID := make(map[string]*collector.Record, len(ids))
	for i := range records {
		row := &records[i]
		if row.Resource == nil || row.Resource.ResourceType != awsv1.ResourceTypeEC2AMI {
			continue
		}
		byID[row.Resource.ResourceID] = row
	}
	resolved := make(map[string]struct{}, len(ids))
	if output != nil {
		for _, image := range output.Images {
			detail := amiDetailFromImage(image)
			if detail.imageID == "" {
				continue
			}
			resolved[detail.imageID] = struct{}{}
			if row, ok := byID[detail.imageID]; ok && row.Resource != nil {
				row.Resource.Attributes = detail.attributes()
			}
		}
	}
	unresolved := 0
	for _, id := range ids {
		if _, ok := resolved[id]; !ok {
			unresolved++
		}
	}
	if unresolved > 0 {
		denials = append(denials, optionalDenial{
			operation: "DescribeImages",
			resource:  "region:" + region,
			effect:    "ami-image-unresolved",
			message: fmt.Sprintf("DescribeImages left %d AMI image(s) unresolved for region:%s; ami-image-unresolved",
				unresolved, region),
			attributes: map[string]any{"unresolved_count": unresolved},
		})
	}
	if len(denials) == 0 {
		return nil, nil
	}
	return &optionalReadDenied{denials: denials}, nil
}

// isAMIDescribeDenial recognizes the EC2 authorization errors for the one
// reviewed optional enrichment. Other API and transport failures stay fatal.
func isAMIDescribeDenial(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "UnauthorizedOperation", "AccessDenied", "AccessDeniedException":
		return true
	default:
		return false
	}
}
