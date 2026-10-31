// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// ecrDescribeImagesInput scopes DescribeImages to the owning registry,
// matching the in-tree adapter: a blank registry resolves in the caller
// account, so cross-account repositories keep their own registry.
func ecrDescribeImagesInput(repository ecrtypes.Repository) *awsecr.DescribeImagesInput {
	input := &awsecr.DescribeImagesInput{
		RepositoryName: repository.RepositoryName,
	}
	if registry := strings.TrimSpace(aws.ToString(repository.RegistryId)); registry != "" {
		input.RegistryId = aws.String(registry)
	}
	return input
}

// ecrImageRecords retains the placeholder image record and one typed reference
// for each image tag. An untagged digest receives one empty-tag reference.
func ecrImageRecords(repositoryARN, repositoryName string, image ecrtypes.ImageDetail, region string) []collector.Record {
	digest := aws.ToString(image.ImageDigest)
	tags := image.ImageTags
	if len(tags) == 0 {
		tags = []string{""}
	}
	name := aws.ToString(image.RepositoryName)
	placeholderTag := digest
	if len(image.ImageTags) > 0 {
		placeholderTag = image.ImageTags[0]
	}
	result := []collector.Record{record(repositoryARN+"@"+digest, "ecr", region, repositoryName+":"+placeholderTag, "image")}
	for _, tag := range tags {
		result = append(result, collector.Record{TypedOnly: true, ImageReference: &collector.LiveImageReference{
			Region: region, ServiceKind: "ecr", RepositoryARN: repositoryARN,
			RepositoryName: name, RegistryID: aws.ToString(image.RegistryId),
			ImageDigest: digest, ManifestDigest: digest, Tag: tag,
			PushedAt: aws.ToTime(image.ImagePushedAt), ImageSizeInBytes: aws.ToInt64(image.ImageSizeInBytes),
			ManifestMediaType: aws.ToString(image.ImageManifestMediaType), ArtifactMediaType: aws.ToString(image.ArtifactMediaType),
		}})
	}
	return result
}

// appendUniqueECRImageRecords suppresses repeated details from later pages
// before they can add either placeholder records or typed references.
func appendUniqueECRImageRecords(records []collector.Record, seen map[string]struct{}, repositoryARN, repositoryName string, image ecrtypes.ImageDetail, region string) []collector.Record {
	key := ecrImageDedupeKey(repositoryARN, image)
	if _, exists := seen[key]; exists {
		return records
	}
	seen[key] = struct{}{}
	return append(records, ecrImageRecords(repositoryARN, repositoryName, image, region)...)
}

// ecrImageDedupeKey matches the legacy adapter's per-repository image key.
// Tag order does not distinguish repeated DescribeImages rows across pages.
func ecrImageDedupeKey(repositoryARN string, image ecrtypes.ImageDetail) string {
	tags := append([]string(nil), image.ImageTags...)
	sort.Strings(tags)
	return strings.Join([]string{
		strings.TrimSpace(repositoryARN),
		strings.TrimSpace(aws.ToString(image.RepositoryName)),
		strings.TrimSpace(aws.ToString(image.RegistryId)),
		strings.TrimSpace(aws.ToString(image.ImageDigest)),
		strings.Join(tags, "\x00"),
	}, "\x00")
}
