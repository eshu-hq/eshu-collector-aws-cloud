// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"strings"
	"testing"

	awstagging "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
)

// TestSSMBulkTagCallCounts is the decision 3.3 call-count gate: the fixture
// walk performs one DescribeParameters call, exactly one GetResources page,
// and zero ListTagsForResource calls (any serial call fails the stub).
func TestSSMBulkTagCallCounts(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, calls := wave1SSMStubConfig(t, fixture)
	if _, err := listSSM(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got := calls.Describe.Load(); got != 1 {
		t.Fatalf("DescribeParameters calls = %d, want 1", got)
	}
	if got := calls.GetResources.Load(); got != 1 {
		t.Fatalf("GetResources calls = %d, want 1 page for the 3-row fixture", got)
	}
	if got := calls.ListTags.Load(); got != 0 {
		t.Fatalf("ListTagsForResource calls = %d, want 0", got)
	}
}

// TestSSMBulkTagAbsentMeansNil pins bulk-absent ⇒ nil: the untagged fixture
// row has no bulk entry and must stay tag-nil, never an empty map.
func TestSSMBulkTagAbsentMeansNil(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, _ := wave1SSMStubConfig(t, fixture)
	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Resource == nil {
			continue
		}
		if record.Resource.ResourceID == "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/app/config" && record.Resource.Tags != nil {
			t.Fatalf("bulk-absent parameter tags = %#v, want nil", record.Resource.Tags)
		}
	}
}

// TestSSMBulkTagARNLessJoinsBySuffix pins the ARN-less join rule: the
// Describe row without an ARN rejoins its bulk entry by the
// ":parameter"+name suffix and carries the exact fixture tag map.
func TestSSMBulkTagARNLessJoinsBySuffix(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, _ := wave1SSMStubConfig(t, fixture)
	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Resource == nil {
			continue
		}
		if record.Resource.ResourceID != "/wave1/ami/latest" {
			continue
		}
		if len(record.Resource.Tags) != 1 || record.Resource.Tags["env"] != "wave1" {
			t.Fatalf("ARN-less parameter tags = %#v, want map[env:wave1]", record.Resource.Tags)
		}
		return
	}
	t.Fatal("ARN-less parameter record missing")
}

// TestSSMBulkTagDuplicateARNFailsLeg pins fail-closed mapping integrity: a
// bulk ARN seen twice fails the leg with a named error, never a merged map.
func TestSSMBulkTagDuplicateARNFailsLeg(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	arn := "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password"
	cfg, _ := wave1SSMStubConfig(t, fixture, withSSMStubBulkPages(
		[]map[string]any{
			wave1SSMStubMapping(arn, map[string]string{"env": "wave1"}),
			wave1SSMStubMapping(arn, map[string]string{"env": "wave1"}),
		},
	))
	_, err := listSSM(context.Background(), cfg)
	assertSSMBulkLegError(t, err, "duplicate")
}

// TestSSMBulkTagEmptyARNFailsLeg pins fail-closed mapping shape: a bulk entry
// without a resource ARN fails the leg instead of joining nothing.
func TestSSMBulkTagEmptyARNFailsLeg(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, _ := wave1SSMStubConfig(t, fixture, withSSMStubBulkPages(
		[]map[string]any{
			wave1SSMStubMapping("", map[string]string{"env": "wave1"}),
		},
	))
	_, err := listSSM(context.Background(), cfg)
	assertSSMBulkLegError(t, err, "without ARN")
}

// TestSSMBulkTagAmbiguousSuffixFailsLeg pins deterministic ARN-less joins:
// two bulk ARNs sharing one row's name suffix fail the leg instead of
// picking one.
func TestSSMBulkTagAmbiguousSuffixFailsLeg(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, _ := wave1SSMStubConfig(t, fixture, withSSMStubBulkPages(
		[]map[string]any{
			wave1SSMStubMapping("arn:aws:ssm:us-east-1:111122223333:parameter/wave1/ami/latest", map[string]string{"env": "a"}),
			wave1SSMStubMapping("arn:aws:ssm:us-east-1:123456789012:parameter/wave1/ami/latest", map[string]string{"env": "b"}),
		},
	))
	_, err := listSSM(context.Background(), cfg)
	assertSSMBulkLegError(t, err, "ambiguous")
}

// TestSSMBulkTagThrottleFailsNamed pins the throttle gate: a throttled bulk
// walk fails the leg with a named error, never an optional denial (decision
// 1.4 rerouting stays closed).
func TestSSMBulkTagThrottleFailsNamed(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, _ := wave1SSMStubConfig(t, fixture,
		withSSMStubBulkError(400, "ThrottlingException", "Rate exceeded"))
	_, err := listSSM(context.Background(), cfg)
	assertSSMBulkLegError(t, err, "ssm bulk tags")
}

// TestSSMBulkTagDenialFailsNamed pins the denial gate: a denied bulk walk
// fails the leg with a named error, never an optional denial.
func TestSSMBulkTagDenialFailsNamed(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, _ := wave1SSMStubConfig(t, fixture,
		withSSMStubBulkError(403, "AccessDeniedException", "not authorized"))
	_, err := listSSM(context.Background(), cfg)
	assertSSMBulkLegError(t, err, "ssm bulk tags")
}

// TestSSMBulkTagPaginationTraversal pins token traversal: mappings spread
// across two bulk pages merge into one map behind two GetResources calls.
func TestSSMBulkTagPaginationTraversal(t *testing.T) {
	t.Parallel()

	fixture := loadWave1SSMFixture(t)
	cfg, calls := wave1SSMStubConfig(t, fixture, withSSMStubBulkPages(
		[]map[string]any{
			wave1SSMStubMapping("arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password", map[string]string{"env": "wave1"}),
		},
		[]map[string]any{
			wave1SSMStubMapping("arn:aws:ssm:us-east-1:123456789012:parameter/wave1/ami/latest", map[string]string{"env": "wave1"}),
		},
	))
	bulk, err := ssmBulkTagMap(context.Background(), awstagging.NewFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(bulk) != 2 {
		t.Fatalf("bulk map size = %d, want 2 across two pages", len(bulk))
	}
	if got := calls.GetResources.Load(); got != 2 {
		t.Fatalf("GetResources calls = %d, want 2 pages", got)
	}
}

// assertSSMBulkLegError pins the named-error contract every bulk leg failure
// shares: a non-nil error naming the bulk source that is never an optional
// read denial.
func assertSSMBulkLegError(t *testing.T, err error, wantSubstr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("listSSM error = nil, want substring %q", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("listSSM error = %q, want substring %q", err, wantSubstr)
	}
	var denied *optionalReadDenied
	if errors.As(err, &denied) {
		t.Fatalf("listSSM error = %q, want a hard leg failure, not an optional denial", err)
	}
}
