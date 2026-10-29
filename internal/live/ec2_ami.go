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
// #9301 contract admits, plus the conditionally admitted Name under
// eshu-hq/eshu#9525. It carries no description field by construction:
// creator-controlled prose never enters the producer. The admitted name stays
// untrusted creator-controlled text: admission claims structural validity
// only, never secret-freedom (see inspectAMIName).
type amiImageDetail struct {
	imageID         string
	name            string
	nameDropped     bool
	platformDetails string
	platform        string
	architecture    string
	creationDate    string
	deprecationTime string
	ownerAlias      string
	rootDeviceType  string
}

// attributes returns the admitted attribute map: the typed fields plus the
// validated name. Absent and blank values stay omitted; unparseable
// timestamps are dropped, never synthesized; a dropped name stays absent and
// warns once per scan via the ami_name_dropped effect.
func (detail amiImageDetail) attributes() map[string]any {
	attrs := map[string]any{}
	if detail.name != "" {
		attrs["name"] = detail.name
	}
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

// amiDetailFromImage projects one SDK image onto the admitted fields. The
// image Name passes the #9525 structural admission (inspectAMIName); a
// dropped name keeps the AMI id and typed fields and warns once per scan.
// The image Description is deliberately never read: prose admission is
// permanently excluded, so exclusion holds by construction.
func amiDetailFromImage(image ec2types.Image) amiImageDetail {
	verdict := inspectAMIName(aws.ToString(image.Name))
	detail := amiImageDetail{
		imageID:         strings.TrimSpace(aws.ToString(image.ImageId)),
		platformDetails: aws.ToString(image.PlatformDetails),
		platform:        string(image.Platform),
		architecture:    string(image.Architecture),
		creationDate:    aws.ToString(image.CreationDate),
		deprecationTime: aws.ToString(image.DeprecationTime),
		ownerAlias:      aws.ToString(image.ImageOwnerAlias),
		rootDeviceType:  string(image.RootDeviceType),
	}
	if verdict.admit {
		detail.name = verdict.value
	}
	detail.nameDropped = verdict.drop
	return detail
}

// appendAMIDetails resolves the scan's deduplicated AMI ids through one
// bounded DescribeImages call and stamps the admitted fields onto the
// matching AMI records. Identity records and the instance relationship survive
// every degradation path: a denial degrades to one warning, a truncated set
// warns with the dropped count, and images the call cannot see warn as
// unresolved without inferring an OS version or a reason. An unknown or
// invisible id fails the whole batched call with InvalidAMIID.NotFound or
// InvalidAMIID.Unavailable; that error isolates the bad ids per id instead of
// failing the scan. A non-denial transport failure stays fatal.
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
		if isAMIImageNotFound(err) {
			return appendAMIDetailsSingles(ctx, client, region, records, ids, denials)
		}
		return nil, fmt.Errorf("ec2 describe images: %w", err)
	}
	byID := indexAMIRecords(records, len(ids))
	var images []ec2types.Image
	if output != nil {
		images = output.Images
	}
	resolved, nameDropped := stampAMIDetails(byID, images)
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
	denials = appendAMINameDroppedDenial(denials, region, nameDropped)
	if len(denials) == 0 {
		return nil, nil
	}
	return &optionalReadDenied{denials: denials}, nil
}

// indexAMIRecords maps the scan's AMI identity records by AMI id for stamping.
func indexAMIRecords(records []collector.Record, size int) map[string]*collector.Record {
	byID := make(map[string]*collector.Record, size)
	for i := range records {
		row := &records[i]
		if row.Resource == nil || row.Resource.ResourceType != awsv1.ResourceTypeEC2AMI {
			continue
		}
		byID[row.Resource.ResourceID] = row
	}
	return byID
}

// stampAMIDetails projects each image onto the admitted fields of its AMI
// record and reports the stamped ids plus the dropped-name count. Images the
// scan never referenced still stamp when present; callers count unresolved
// ids against the request. The dropped count covers stamped records only —
// the facts the scan actually emits — and feeds one deduped
// ami_name_dropped warning per scan, never one per image.
func stampAMIDetails(byID map[string]*collector.Record, images []ec2types.Image) (map[string]struct{}, int) {
	resolved := make(map[string]struct{}, len(images))
	nameDropped := 0
	for _, image := range images {
		detail := amiDetailFromImage(image)
		if detail.imageID == "" {
			continue
		}
		resolved[detail.imageID] = struct{}{}
		if row, ok := byID[detail.imageID]; ok && row.Resource != nil {
			row.Resource.Attributes = detail.attributes()
			if detail.nameDropped {
				nameDropped++
			}
		}
	}
	return resolved, nameDropped
}

// appendAMINameDroppedDenial records one deduped ami_name_dropped warning for
// the scan when stamping dropped at least one name. The message and attributes
// carry the effect and the dropped count only — never the raw text, which
// stays out of diagnostics under the redacted-marker rule.
func appendAMINameDroppedDenial(denials []optionalDenial, region string, dropped int) []optionalDenial {
	if dropped == 0 {
		return denials
	}
	return append(denials, optionalDenial{
		operation: "DescribeImages",
		resource:  "region:" + region,
		effect:    "ami_name_dropped",
		message: fmt.Sprintf("DescribeImages dropped %d inadmissible AMI name(s) for region:%s; ami_name_dropped",
			dropped, region),
		attributes: map[string]any{"dropped_count": dropped},
	})
}

// appendAMIDetailsSingles isolates unknown or invisible AMI ids after the
// batched call failed with InvalidAMIID.NotFound or InvalidAMIID.Unavailable.
// Each id resolves alone: survivors stamp the admitted typed fields and the
// unresolvable ids count toward one ami-image-unresolved warning. A denial on
// a single degrades the whole enrichment to ami-details-unavailable; any other
// single failure stays fatal. This path only runs after a whole-batch failure,
// so the extra calls stay off the healthy path.
func appendAMIDetailsSingles(ctx context.Context, client *awsec2.Client, region string, records []collector.Record, ids []string, denials []optionalDenial) (*optionalReadDenied, error) {
	var images []ec2types.Image
	for _, id := range ids {
		output, err := client.DescribeImages(ctx, &awsec2.DescribeImagesInput{
			ImageIds:          []string{id},
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
			if isAMIImageNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("ec2 describe images: %w", err)
		}
		if output != nil {
			images = append(images, output.Images...)
		}
	}
	resolved, nameDropped := stampAMIDetails(indexAMIRecords(records, len(ids)), images)
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
	denials = appendAMINameDroppedDenial(denials, region, nameDropped)
	if len(denials) == 0 {
		return nil, nil
	}
	return &optionalReadDenied{denials: denials}, nil
}

// isAMIImageNotFound recognizes the EC2 unknown-or-invisible-image errors for
// the reviewed optional enrichment. Unlike a denial, these name unresolvable
// ids rather than an unavailable call, so the caller isolates the bad ids and
// stamps the survivors instead of failing the scan.
func isAMIImageNotFound(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "InvalidAMIID.NotFound", "InvalidAMIID.Unavailable":
		return true
	default:
		return false
	}
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
