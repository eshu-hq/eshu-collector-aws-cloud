// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

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
