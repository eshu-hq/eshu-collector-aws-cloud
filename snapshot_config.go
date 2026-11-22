// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SnapshotConfig names the satellite-local snapshot directory and its
// lifecycle bounds. The zero value selects every default.
type SnapshotConfig struct {
	// Dir is the snapshot directory. Empty selects the default path.
	Dir string
	// TTL bounds snapshot survival. Non-positive selects the default.
	TTL time.Duration
	// MaxBytes caps one snapshot file. Non-positive selects the default.
	MaxBytes int64
}

// DefaultSnapshotConfig returns the STEP-2 parameters: default directory,
// 2 h TTL, 256 MiB cap.
func DefaultSnapshotConfig() SnapshotConfig {
	return SnapshotConfig{
		Dir:      defaultSnapshotDir(),
		TTL:      DefaultSnapshotTTL,
		MaxBytes: MaxSnapshotBytes,
	}
}

func defaultSnapshotDir() string {
	return filepath.Join(os.TempDir(), "eshu-aws-cloud-snapshots")
}

// ParseSnapshotConfig reads the optional snapshot block from the satellite
// config surface alongside limits.*: snapshot.dir (string) and
// snapshot.ttlSeconds (positive integer). Absent or partial blocks select
// defaults; malformed values fail closed.
func ParseSnapshotConfig(config map[string]any) (SnapshotConfig, error) {
	cfg := DefaultSnapshotConfig()
	block, ok := config["snapshot"]
	if block == nil || !ok {
		return cfg, nil
	}
	obj, ok := block.(map[string]any)
	if !ok {
		return SnapshotConfig{}, fmt.Errorf("config %q must be an object", "snapshot")
	}
	if raw, present := obj["dir"]; present {
		dir, ok := raw.(string)
		if !ok {
			return SnapshotConfig{}, fmt.Errorf("config %q must be a string", "snapshot.dir")
		}
		if strings.TrimSpace(dir) != "" {
			cfg.Dir = dir
		}
	}
	if raw, present := obj["ttlSeconds"]; present {
		seconds, ok := raw.(float64)
		if !ok || seconds != float64(int(seconds)) || seconds <= 0 {
			return SnapshotConfig{}, fmt.Errorf("config %q must be a positive integer", "snapshot.ttlSeconds")
		}
		cfg.TTL = time.Duration(int(seconds)) * time.Second
	}
	return cfg, nil
}

// SnapshotStore persists one digest-addressed snapshot file per walk
// attempt in a satellite-local directory. One satellite process serves one
// page call, so the directory (not process memory) is what survives
// between pages.
type SnapshotStore struct {
	dir      string
	ttl      time.Duration
	maxBytes int64
}

// NewSnapshotStore creates the snapshot directory (0700: snapshot files
// carry fact payloads) and binds the lifecycle bounds. An unwritable path
// fails closed instead of serving walks with no persistence behind them.
func NewSnapshotStore(cfg SnapshotConfig) (*SnapshotStore, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		cfg.Dir = defaultSnapshotDir()
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultSnapshotTTL
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = MaxSnapshotBytes
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("snapshot directory %q: %w", cfg.Dir, err)
	}
	return &SnapshotStore{dir: cfg.Dir, ttl: cfg.TTL, maxBytes: cfg.MaxBytes}, nil
}

// Dir reports the snapshot directory the store persists into.
func (s *SnapshotStore) Dir() string {
	return s.dir
}
