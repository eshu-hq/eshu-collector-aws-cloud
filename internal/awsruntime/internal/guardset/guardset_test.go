// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package guardset_test

import (
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/internal/awsruntime/internal/guardset"
)

// TestServiceFromImportPath covers the extraction of the service token from a
// runtimebind blank-import path, including the non-runtimebind and malformed
// cases the parser must ignore.
func TestServiceFromImportPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
		ok   bool
	}{
		{
			name: "canonical runtimebind import",
			path: "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/iam/runtimebind",
			want: "iam",
			ok:   true,
		},
		{
			name: "multi-word service token",
			path: "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/cloudwatchlogs/runtimebind",
			want: "cloudwatchlogs",
			ok:   true,
		},
		{
			name: "nested service import reports the relative token",
			path: "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/catalog/app_registry/runtimebind",
			want: "catalog/app_registry",
			ok:   true,
		},
		{
			name: "non-runtimebind service import is ignored",
			path: "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/iam",
			want: "",
			ok:   false,
		},
		{
			name: "unrelated import is ignored",
			path: "github.com/eshu-hq/eshu-collector-aws-cloud/internal/awsruntime",
			want: "",
			ok:   false,
		},
		{
			name: "deeper nested package under runtimebind is ignored",
			path: "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/iam/runtimebind/extra",
			want: "",
			ok:   false,
		},
		{
			name: "fourth service level is ignored",
			path: "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/a/b/c/runtimebind",
			want: "",
			ok:   false,
		},
		{
			name: "empty path",
			path: "",
			want: "",
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := guardset.ServiceFromImportPath(tc.path)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("ServiceFromImportPath(%q) = (%q, %v), want (%q, %v)", tc.path, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestDiff is the core guard proof. It must report a difference whenever the
// directory set and the import set disagree, and report none when they match.
// The "dir present but not imported" case is the real failure mode the guard
// protects against: a scanner author adds service/<x>/runtimebind/ but forgets
// the bindings.go blank import.
func TestDiff(t *testing.T) {
	cases := []struct {
		name        string
		dirs        []string
		imports     []string
		wantMissing []string // in dirs, absent from imports
		wantExtra   []string // in imports, absent from dirs
	}{
		{
			name:    "identical sets have no diff",
			dirs:    []string{"iam", "s3", "ec2"},
			imports: []string{"ec2", "iam", "s3"},
		},
		{
			name:        "runtimebind dir present but not imported is missing",
			dirs:        []string{"iam", "s3", "newscanner"},
			imports:     []string{"iam", "s3"},
			wantMissing: []string{"newscanner"},
		},
		{
			name:      "import present but no runtimebind dir is extra",
			dirs:      []string{"iam", "s3"},
			imports:   []string{"iam", "s3", "ghost"},
			wantExtra: []string{"ghost"},
		},
		{
			name:        "both directions can diff at once",
			dirs:        []string{"iam", "onlydir"},
			imports:     []string{"iam", "onlyimport"},
			wantMissing: []string{"onlydir"},
			wantExtra:   []string{"onlyimport"},
		},
		{
			name:    "both empty have no diff",
			dirs:    nil,
			imports: nil,
		},
		{
			name:        "duplicate entries are de-duplicated before diffing",
			dirs:        []string{"iam", "iam", "s3"},
			imports:     []string{"iam"},
			wantMissing: []string{"s3"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			missing, extra := guardset.Diff(tc.dirs, tc.imports)
			if !equalSorted(missing, tc.wantMissing) {
				t.Errorf("Diff missing = %v, want %v", missing, tc.wantMissing)
			}
			if !equalSorted(extra, tc.wantExtra) {
				t.Errorf("Diff extra = %v, want %v", extra, tc.wantExtra)
			}
		})
	}
}

// TestRuntimebindServiceDirs proves the filesystem reader finds the real
// service runtimebind directories from the live tree, independent of any
// hardcoded list or the registry.
//
// NOTE(port): runtimebind packages are class-(c) (blocked on
// awsruntime.Register, which needs core telemetry/collector), so the ported
// tree has no runtimebind directories. This pins that documented absence:
// the reader still works, it finds the empty set. See NOT_PORTED.md.
func TestRuntimebindServiceDirs(t *testing.T) {
	servicesDir := liveServicesDir(t)
	dirs, err := guardset.RuntimebindServiceDirs(servicesDir)
	if err != nil {
		t.Fatalf("RuntimebindServiceDirs() error = %v", err)
	}
	if len(dirs) != 0 {
		t.Fatalf("RuntimebindServiceDirs() = %v, want empty (runtimebind not ported)", dirs)
	}
}

// TestBindingsImportServices proves the source reader extracts the service set
// from the live bindings.go and that it agrees with the directory walk. This is
// the assertion the guard tests rely on, exercised here against real inputs so
// the helpers are proven before the guard tests wire them together.
//
// NOTE(port): bindings.go is class-(c) (same Register block as above), so the
// ported tree has no bindings file. This pins that documented absence: the
// reader reports a clean open error instead of a phantom set.
func TestBindingsImportServices(t *testing.T) {
	bindingsFile := liveBindingsFile(t)
	imports, err := guardset.BindingsImportServices(bindingsFile)
	if err == nil {
		t.Fatalf("BindingsImportServices() = %v, want an open error (bindings.go not ported)", imports)
	}
}

// liveServicesDir resolves the ported internal/service tree from this test
// file's location so the walk does not depend on the working directory.
//
// NOTE(port): in-tree this is go/internal/collector/awscloud/service; the
// port maps service/ to internal/service/ per the package map.
func liveServicesDir(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	// guardset_test.go -> guardset -> internal -> awsruntime -> internal -> module root
	rootDir := filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "..")
	return filepath.Join(rootDir, "internal", "service")
}

// liveBindingsFile resolves the live bindings.go source from this test file's
// location.
func liveBindingsFile(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	// guardset_test.go -> guardset -> internal -> awsruntime
	awsruntimeDir := filepath.Join(filepath.Dir(currentFile), "..", "..")
	return filepath.Join(awsruntimeDir, "bindings", "bindings.go")
}

func equalSorted(a, b []string) bool {
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	if len(ac) == 0 && len(bc) == 0 {
		return true
	}
	return reflect.DeepEqual(ac, bc)
}
