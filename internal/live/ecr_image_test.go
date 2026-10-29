// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestECRImageReferencesPreserveTagsAndDigest(t *testing.T) {
	pushed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	image := ecrtypes.ImageDetail{
		RepositoryName: aws.String("team/api"), RegistryId: aws.String("123456789012"),
		ImageDigest: aws.String("sha256:abc"), ImageTags: []string{"latest", "v1"},
		ImagePushedAt: &pushed, ImageSizeInBytes: aws.Int64(42),
		ImageManifestMediaType: aws.String("application/vnd.oci.image.manifest.v1+json"),
	}
	got := ecrImageRecords("arn:aws:ecr:us-east-1:123456789012:repository/team/api", "team/api", image, "us-east-1")
	if len(got) != 3 || got[1].ImageReference == nil || got[2].ImageReference == nil {
		t.Fatalf("image references = %#v", got)
	}
	if got[1].ImageReference.Tag != "latest" || got[2].ImageReference.Tag != "v1" || got[1].ImageReference.ManifestDigest != "sha256:abc" || got[1].ImageReference.ImageSizeInBytes != 42 {
		t.Fatalf("image metadata = %#v", got)
	}
	image.ImageTags = nil
	untagged := ecrImageRecords("", "team/api", image, "us-east-1")
	if len(untagged) != 2 || untagged[1].ImageReference.Tag != "" {
		t.Fatalf("untagged image = %#v", untagged)
	}
}

func TestECRImageDedupeKeyIgnoresTagOrderButKeepsRegistry(t *testing.T) {
	base := ecrtypes.ImageDetail{RepositoryName: aws.String("team/api"), RegistryId: aws.String("123456789012"), ImageDigest: aws.String("sha256:abc"), ImageTags: []string{"latest", "v1"}}
	reordered := base
	reordered.ImageTags = []string{"v1", "latest"}
	if ecrImageDedupeKey("arn:aws:ecr:us-east-1:123456789012:repository/team/api", base) != ecrImageDedupeKey("arn:aws:ecr:us-east-1:123456789012:repository/team/api", reordered) {
		t.Fatal("same image with reordered tags must share one key")
	}
	otherRegistry := base
	otherRegistry.RegistryId = aws.String("210987654321")
	if ecrImageDedupeKey("arn:aws:ecr:us-east-1:123456789012:repository/team/api", base) == ecrImageDedupeKey("arn:aws:ecr:us-east-1:123456789012:repository/team/api", otherRegistry) {
		t.Fatal("different registries must keep distinct image keys")
	}
}

func TestECRDuplicateImageDoesNotAddRecords(t *testing.T) {
	image := ecrtypes.ImageDetail{RepositoryName: aws.String("team/api"), RegistryId: aws.String("123456789012"), ImageDigest: aws.String("sha256:abc"), ImageTags: []string{"latest", "v1"}}
	seen := make(map[string]struct{})
	first := appendUniqueECRImageRecords(nil, seen, "repository-arn", "team/api", image, "us-east-1")
	reordered := image
	reordered.ImageTags = []string{"v1", "latest"}
	second := appendUniqueECRImageRecords(first, seen, "repository-arn", "team/api", reordered, "us-east-1")
	if len(first) != 3 || len(second) != len(first) {
		t.Fatalf("first/duplicate record counts = %d/%d, want 3/3", len(first), len(second))
	}
}
