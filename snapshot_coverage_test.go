// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSnapshotConfigTable(t *testing.T) {
	def := DefaultSnapshotConfig()
	cases := map[string]struct {
		config  map[string]any
		want    SnapshotConfig
		wantErr string
	}{
		"absent block selects defaults": {config: map[string]any{}, want: def},
		"nil block selects defaults":    {config: map[string]any{"snapshot": nil}, want: def},
		"non-object fails closed": {
			config:  map[string]any{"snapshot": "x"},
			wantErr: "must be an object",
		},
		"non-string dir fails closed": {
			config:  map[string]any{"snapshot": map[string]any{"dir": 3}},
			wantErr: "snapshot.dir",
		},
		"blank dir keeps default": {
			config: map[string]any{"snapshot": map[string]any{"dir": "  "}},
			want:   def,
		},
		"valid dir and ttl": {
			config: map[string]any{"snapshot": map[string]any{"dir": t.TempDir(), "ttlSeconds": float64(60)}},
			want:   SnapshotConfig{Dir: "", TTL: 60 * time.Second},
		},
		"string ttl fails closed": {
			config:  map[string]any{"snapshot": map[string]any{"ttlSeconds": "60"}},
			wantErr: "ttlSeconds",
		},
		"fractional ttl fails closed": {
			config:  map[string]any{"snapshot": map[string]any{"ttlSeconds": 1.5}},
			wantErr: "ttlSeconds",
		},
		"zero ttl fails closed": {
			config:  map[string]any{"snapshot": map[string]any{"ttlSeconds": float64(0)}},
			wantErr: "ttlSeconds",
		},
		"negative ttl fails closed": {
			config:  map[string]any{"snapshot": map[string]any{"ttlSeconds": float64(-5)}},
			wantErr: "ttlSeconds",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ParseSnapshotConfig(tc.config)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if blk, ok := tc.config["snapshot"].(map[string]any); ok {
				if wantDir, ok := blk["dir"].(string); ok && strings.TrimSpace(wantDir) != "" && got.Dir != wantDir {
					t.Fatalf("dir = %q, want %q", got.Dir, wantDir)
				}
			}
			if tc.want.TTL != 0 && got.TTL != tc.want.TTL {
				t.Fatalf("ttl = %v, want %v", got.TTL, tc.want.TTL)
			}
			if tc.want.Dir == "" && tc.want.TTL == 0 && got != def {
				t.Fatalf("got %+v, want defaults %+v", got, def)
			}
		})
	}
}

// commitOnePage commits the walk fixture and returns the store, the page
// zero cursor, and the snapshot file path for tamper tests.
func commitOnePage(t *testing.T, store *SnapshotStore) (string, string) {
	t.Helper()
	observed := time.Now().UTC().Truncate(time.Second)
	facts := walkFixture(observed)
	bound := walkBound(t, facts)
	_, page, err := store.CommitWalk(pagedResult(facts, observed), bound)
	if err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}
	if page.Cursor == "" {
		t.Fatal("empty page zero cursor")
	}
	entries, err := os.ReadDir(store.Dir())
	if err != nil || len(entries) == 0 {
		t.Fatalf("snapshot dir read: %v %d", err, len(entries))
	}
	return page.Cursor, filepath.Join(store.Dir(), entries[0].Name())
}

func resumeMustFail(t *testing.T, store *SnapshotStore, cursor string, want string) {
	t.Helper()
	_, _, err := store.ResumeWalk(&PageContinuation{Cursor: cursor}, 1<<20)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want containing %q", err, want)
	}
}

func TestResumeWalkRejectsTamperedSnapshots(t *testing.T) {
	newCommitted := func(t *testing.T) (*SnapshotStore, string, string) {
		t.Helper()
		store := newWalkStore(t)
		cursor, path := commitOnePage(t, store)
		return store, cursor, path
	}

	t.Run("nil cursor", func(t *testing.T) {
		store := newWalkStore(t)
		if _, _, err := store.ResumeWalk(nil, 1<<20); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		store, cursor, path := newCommitted(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		resumeMustFail(t, store, cursor, "is gone")
	})

	t.Run("corrupt file", func(t *testing.T) {
		store, cursor, path := newCommitted(t)
		if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
			t.Fatal(err)
		}
		resumeMustFail(t, store, cursor, "corrupt")
	})

	t.Run("version mismatch", func(t *testing.T) {
		store, cursor, path := newCommitted(t)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc["v"] = float64(999)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		resumeMustFail(t, store, cursor, "unsupported")
	})

	t.Run("total mismatch", func(t *testing.T) {
		store, cursor, path := newCommitted(t)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc["total"] = float64(7)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		resumeMustFail(t, store, cursor, "binds")
	})

	t.Run("page out of range", func(t *testing.T) {
		store, cursor, _ := newCommitted(t)
		decoded, err := decodePageCursor(cursor)
		if err != nil {
			t.Fatal(err)
		}
		decoded.NextPage = 99
		recut, err := encodePageCursor(decoded)
		if err != nil {
			t.Fatal(err)
		}
		resumeMustFail(t, store, recut, "resumes at page")
	})

	t.Run("generation mismatch", func(t *testing.T) {
		store, cursor, _ := newCommitted(t)
		decoded, err := decodePageCursor(cursor)
		if err != nil {
			t.Fatal(err)
		}
		decoded.GenerationID = "generation-other"
		recut, err := encodePageCursor(decoded)
		if err != nil {
			t.Fatal(err)
		}
		// The snapshot file name carries the generation, so move it to
		// match: the resume must then fail on content, not absence.
		entries, err := os.ReadDir(store.Dir())
		if err != nil || len(entries) != 1 {
			t.Fatalf("want 1 snapshot file: %v %d", err, len(entries))
		}
		newName := snapshotFileName(decoded.InstanceID, decoded.GenerationID, decoded.Snapshot)
		if err := os.Rename(filepath.Join(store.Dir(), entries[0].Name()), filepath.Join(store.Dir(), newName)); err != nil {
			t.Fatal(err)
		}
		resumeMustFail(t, store, recut, "generation moved")
	})

	t.Run("expired ttl", func(t *testing.T) {
		dir := t.TempDir()
		writer, err := NewSnapshotStore(SnapshotConfig{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		cursor, _ := commitOnePage(t, writer)
		reader, err := NewSnapshotStore(SnapshotConfig{Dir: dir, TTL: time.Nanosecond})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
		resumeMustFail(t, reader, cursor, "older than the TTL")
	})
}

func TestSecondCommitSupersedesFirst(t *testing.T) {
	store := newWalkStore(t)
	observed := time.Now().UTC().Truncate(time.Second)
	facts := walkFixture(observed)
	bound := walkBound(t, facts)
	if _, _, err := store.CommitWalk(pagedResult(facts, observed), bound); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if _, _, err := store.CommitWalk(pagedResult(facts, observed), bound); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("supersede left %d files, want 1", len(entries))
	}
}

func TestSanitizeFileComponentTable(t *testing.T) {
	for in, want := range map[string]string{
		"abcXYZ019": "abcXYZ019",
		"a/b":       "a_b",
		"":          "x",
		"a.b":       "a.b",
		"a b":       "a_b",
	} {
		if got := sanitizeFileComponent(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeFileComponent(""); got != "x" {
		t.Fatalf("empty = %q", got)
	}
	long := strings.Repeat("a", 100)
	if got := sanitizeFileComponent(long); len(got) != 64 {
		t.Fatalf("truncated len = %d", len(got))
	}
	if got := sanitizeFileComponent("a/b c"); got != "a_b_c" {
		t.Fatalf("mixed = %q", got)
	}
}

func TestCommitWalkEarlyExitsAndCap(t *testing.T) {
	store := newWalkStore(t)
	observed := time.Now().UTC().Truncate(time.Second)

	nonFinal := pagedResult(walkFixture(observed), observed)
	nonFinal.State = "in_progress"
	if _, _, err := store.CommitWalk(nonFinal, 1<<20); err != nil {
		t.Fatalf("non-final state: %v", err)
	}
	empty := pagedResult(nil, observed)
	if _, _, err := store.CommitWalk(empty, 1<<20); err != nil {
		t.Fatalf("empty facts: %v", err)
	}
	tiny, err := NewSnapshotStore(SnapshotConfig{Dir: t.TempDir(), MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tiny.CommitWalk(pagedResult(walkFixture(observed), observed), 1<<20); err != nil {
		t.Fatalf("cap terminal: %v", err)
	}
}

func TestPersistReportsMissingDir(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSnapshotStore(SnapshotConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Truncate(time.Second)
	if _, _, err := store.CommitWalk(pagedResult(walkFixture(observed), observed), 1<<20); err == nil {
		t.Fatal("expected temp file error")
	}
}

func TestSweepReportsUnreadableDir(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSnapshotStore(SnapshotConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Sweep(); err == nil {
		t.Fatal("expected sweep error on removed dir")
	}
}
