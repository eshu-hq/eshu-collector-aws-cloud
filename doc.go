// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the standalone Eshu AWS Cloud collector
// (github.com/eshu-hq/eshu-collector-aws-cloud): one process-adapter
// component that turns AWS API observations into versioned fact families
// for the core reducer. The current emission contract (Contract) declares
// three transitional placeholder kinds; the thirteen core-owned AWS fact
// kinds at schema 1.0.0 await the logic port in PORT_PLAN.md.
//
// Boundary: this package imports only the published SDK modules
// (eshu-sdk/collector, eshu-sdk/factschema). It never imports go/internal,
// another collector implementation, or any core Postgres/graph/queue
// handle. Every one of those would fail the import-boundary test and block
// cutover per #4047.
package collector
