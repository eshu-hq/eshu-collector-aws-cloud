// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package live implements the config-driven live AWS read path for the
// standalone collector. The SDK stdio entry point serves two modes: a local
// file mode (config source.input, kept for fixtures and offline proof) and
// the live mode built here, where the host activation config names a target
// account, region and service allowlists, and limits, and this package lists
// live AWS resources into a collector.Report the existing collector.Collect
// turns into SDK facts.
//
// Authentication is the ambient AWS chain only (IRSA web identity, ECS/EKS
// role, instance profile, environment): this package never accepts static
// credentials, credential keys, or secret values, and every emitted record
// carries control-plane metadata only, mirroring the in-tree scanner
// contracts. Secret values, policy documents, message bodies, and parameter
// values are never read.
package live
