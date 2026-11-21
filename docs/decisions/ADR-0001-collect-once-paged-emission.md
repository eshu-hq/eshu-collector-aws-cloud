# ADR-0001: Collect-once paged emission for Class-3 walks

- Status: proposed
- Date: 2026-11-21

## Context

Issue [eshu-hq/eshu#9635](https://github.com/eshu-hq/eshu/issues/9635)
("Large first scans need bounded emission") is the active Class-3 remedy,
cross-referenced with
[eshu-hq/eshu#11085](https://github.com/eshu-hq/eshu/issues/11085), per the
G1-fail ruling (`/tmp/arbiter-g1-fail-ruling.md` decisions 1-2, 4.2, 5.2,
6.2). The prior #9635 direction stands: satellite-native paged emission
with the checkpoint advancing on next-page ack. This record is the STEP 1
design gate the ruling demands before any C code: no C implementation
exists yet, and none lands without this record.

The defect C removes is the re-collect window. Today every v1alpha3 page
call re-collects from AWS and then splits (`paging.go` `PaginateResult`:
"Every continuation call re-collects"; `cmd/collector/main.go`: "A resumed
v1alpha3 call re-collects and serves its cursor's page"). Each page of a
walk therefore observes the source at a different instant. At iam-child
scale that window fires drift fail-closeds (cursor digest mismatch,
`emitResumePage`) and multiplies provider calls by the page count, which
is the amplification behind the conc8 and SSM-tag throttle deaths. The
canonical fact order (`c89e8d3`) and cursor digest pin make recollects
deterministic for identical sets, but they cannot make the source stand
still across N collects. One collect per walk removes the window itself.

Scope facts this design rests on, all read from this tree at `c89e8d3`:

- One satellite process serves one page call. The host re-invokes the
  binary per page; the request arrives on stdin (`sdkRequest` with an
  optional opaque `continuation.cursor`) and the page leaves on stdout
  (`cmd/collector/main.go` `run`). No in-memory state survives between
  pages. A collect-once snapshot must therefore be satellite-local
  persistent state, not process memory.
- The cursor is opaque to the host: base64url of the satellite's own JSON
  (`encodePageCursor`). The host passes it back verbatim on the next
  call. New satellite-side fields inside the token are invisible to the
  host.
- The resume-failure contract already exists: a drifted source or bad
  cursor fails the run "so the host retries the claim from page zero
  instead of committing torn evidence" (`main.go`, `PaginateResult` doc).
  Failing a walk closed is an established, host-consumed outcome.
- Terminal budget failures already have a satellite-minted failure-class
  shape (`pageBudgetExceeded` with `FailureClassPageBudgetExceeded`),
  so a snapshot-cap terminal needs no new host vocabulary.
- There is no satellite-side fact cache in this tree (no cache symbols;
  the only persisted resume state is the `checkpoint` package's AWS-API
  pagination tokens, which are per-operation, not per-walk). R1a has
  nothing to attach to here.
- Defaults that pin the arithmetic: per-page bound `DefaultMaxPageBytes`
  = 4 MiB stdout cap minus 64 KiB envelope headroom = 4,128,768 bytes;
  claim wall bound 300 s; `TotalFacts` declared on every page
  (`health.go`, `paging.go`).

## Decision

Serve every page of a walk from one collected snapshot. One collect per
walk attempt; pages are deterministic slices of that snapshot; the cursor
binds the snapshot; a dead walk resumes from the snapshot or fails
closed. Nothing is ever silently recollected into a live walk.

### Snapshot lifecycle

1. Page-zero call (no cursor): perform the single collect exactly as
   today (live AWS read, `Collect`/`CollectPartial`, typed-evidence
   append), canonical-order the facts, compute the `PageDigest`, and
   persist the ordered fact stream as one digest-addressed snapshot file
   before serving page 0. Write temp + fsync + atomic rename; the
   filename carries instance, generation, and digest hex only
   (counts/shapes in logs, never raw cloud identifiers).
2. Page-zero mints a cursor binding `(snapshotID = digest, totalFacts,
   generationID, pageBoundUsed)`. The cursor keeps every field it has
   today and gains the snapshot binding inside the opaque token.
3. Resume call (cursor present): load the snapshot file by snapshotID,
   verify its digest and fact count equal the cursor's, split with the
   cursor-pinned page bound, and serve the cursor's page. The generation
   repeats the cursor-pinned values, never a re-collection time
   (existing `emitResumePage` behavior, kept).
4. Any snapshot miss or mismatch (file absent, corrupt, digest or count
   differs) fails the run with the existing retry-from-zero error shape.
   The host retries the claim from page zero, which performs a new
   single collect and mints a new snapshot: the old walk is dead, the
   new walk is self-consistent. A recollect across walks is explicit and
   total; a recollect inside a walk is impossible by construction.
5. Concurrent page-zero calls for one generation (host retry racing a
   live walk) are safe: digest-addressed files never clobber, and each
   walk's cursor binds its own digest. Orphans are reaped by TTL (below).

### Checkpoint-advance-on-ack

The host's request for page N+1 is the delivery ack for page N. The
snapshot is the walk's checkpoint: it must outlive every page serve,
including the final page, whose delivery is never acked. Deletion rule:
a snapshot is deleted only when superseded (a newer snapshot for the
same instance+generation commits) or when its mtime passes the snapshot
TTL. Default TTL is 2 h (STEP-2 parameter; rationale: 2x the 1200 s G2
walk bound plus headroom for host retry spacing). No explicit host
completion signal is required, which is why this needs no wire change.

### Restart rules

- Fork (satellite process) death between pages: the next page call loads
  the surviving snapshot file and serves the identical bytes. Restart is
  resume, not recovery: no replay, no catch-up, no re-emission.
- Snapshot loss (disk gone, wrong volume, TTL expiry, corrupt file):
  fail the walk closed with the retry-from-zero error. The walk does not
  limp on with a partial stream.
- Mid-walk source change (live churn after the collect): later pages are
  byte-identical to the snapshot by design. The walk serves a pinned
  instant, exactly like a database snapshot read. Churn surfaces, if at
  all, on the next walk's page zero, never as mid-walk drift.
- Host retry from page zero after a fail-closed walk: new collect, new
  snapshot, new cursor lineage. Old cursors stay bound to the dead
  snapshot and keep failing closed; they can never attach to the new
  walk because the digest differs.

### Snapshot memory and bytes accounting

Measured on this tree with a scratch harness (deleted before commit;
`FactWireBytes` on `sizedFact` bands plus a 31732-fact split timing,
seeded from the ruling's split-union baseline of 31732 facts):

| Quantity | Measured value |
|---|---|
| Envelope floor per fact (empty payload) | 347 B |
| 150 B payload (tag-observation scale) | 562 B wire |
| 800 B payload (resource scale) | 1212 B wire |
| 4000 B payload (policy-document scale) | 4417 B wire |
| 31732 facts at resource scale, wire sum | 38,776,504 B (~37 MiB), avg 1222 B |
| Canonical sort at 31732 facts | ~89 ms |
| Digest at 31732 facts | ~3 ms |
| Split at 31732 facts | ~63 ms |
| Resume-call redo (re-split) | ~59 ms |
| 31732 facts at policy scale, wire sum | ~140 MB, 35 pages |
| 31732 facts at resource scale, page count | 10 pages at the 4,128,768 B bound |

Bounds the design states (pins, not aspirations):

- Snapshot file cap: 256 MiB (== 64 pages x 4 MiB, the prior ceiling
  arithmetic). Exceeding it is a terminal `snapshot-budget-exceeded`
  failure in the existing `pageBudgetExceeded` shape. Typical walks
  (~37 MiB file at resource scale) sit 7x under the cap; all-large
  policy-scale walks (~140 MB) fit.
- Per-page-call transient memory budget: 512 MiB (snapshot decode ~1x
  file size plus split copies; typical ~120 MB transient). Each call
  loads the full snapshot today; a page-index sidecar (one file read per
  page instead of full decode) is the recorded fallback if G2 serve
  pricing misses, not part of the first cut.
- Serve pricing: resume call ~= snapshot load (100-200 ms at 37 MiB)
  + re-split (~60 ms) + one page encode. Walk serve total ~= collect +
  pages x ~0.3 s, inside the ruling's "collect + <100 s" pricing and the
  1200 s G2 walk bound with two orders of magnitude to spare.
- G2 single-collect target (<=240 s) is already met by the measured
  single-collect walls the ruling records (iam-only 178-185 s, core16
  82 s); C changes none of the collection code, only what happens after
  it.

### Page bound and declared-total pins, unchanged

`DefaultMaxPageBytes`, the `TotalFacts`-on-every-page declaration, the
canonical emission order, and the `PageDigest` keying are byte-for-byte
unchanged. The cursor gains fields inside the opaque token; `ResultPage`
and `PageContinuation` wire shapes are untouched. Existing paging tests
(`paging_test.go`, `paging_resume_test.go`, `paging_split_test.go`,
`cmd/collector/paging_test.go`) must pass unmodified: they pin the
bounds C inherits.

### R1a posture

R1a (cache) may ride inside the C satellite work only if fact-identical
and schedule-free (ruling 1.3/4.2). Finding: there is no satellite cache
to ride on, and C needs none — the snapshot is not a cache (it is the
walk's only truth, digest-bound, TTL-reaped, never served across walks).
If the host memoizes page-zero collect inputs, the satellite-side
acceptance is already satisfiable: identical source sets produce
byte-identical snapshots via the canonical order plus digest. No
satellite code is authorized for R1a; it never gates C.

### SSM rides-C input

C reduces SSM tag-call volume from params x pages (recollect) to params
x 1 (single collect) with identical serve semantics. Whether SSM rides C
is decided by the completed S-E measurements (ruling 4.4), not here;
this record supplies the call-arithmetic shape that verdict consumes. If
a single fresh serial pass throttles alone, an SSM-specific fix is still
needed in addition to C.

## Why no host wire change

1. The cursor is host-opaque. Snapshot binding rides inside a token the
   host already passes back verbatim; `ResultPage` / `PageContinuation`
   shapes do not change.
2. Fail-closed-then-retry-from-zero is already the host-consumed resume
   contract (cited above). C exercises it in exactly one new case
   (snapshot miss), with an identical error shape.
3. New terminal vocabulary (`snapshot-budget-exceeded`) follows the
   existing satellite-minted precedent (`page-budget-exceeded`), which
   the host admission path already handles with byte sizes.
4. Snapshot configuration (directory, TTL) reads from the satellite's
   existing config surface alongside `limits.*`; no new host-to-satellite
   field is required. If STEP 2 proves otherwise, the ruling orders
   re-escalation before code (decision 4.6), and this record would be
   amended first.

## Consequences

Easier: drift becomes structurally impossible within a walk (one
observation instant per walk); provider call counts drop ~pages x, which
is the accuracy-safe throughput lever the throttle bars demand (serial
collection stays, ruling 5.3); serve pricing is measured in
milliseconds, de-risking the G2 walk bound; concurrent page-zero races
are safe by digest addressing.

Harder: the satellite becomes stateful across calls within one walk
(snapshot dir lifecycle, TTL sweeper, disk-full behavior all become
operator surface); resume calls pay a full snapshot load (bounded above,
indexed-serve as fallback); abandoned-walk snapshots linger until TTL.

Watch: snapshot-dir growth rate and TTL reap counts (new operator
metrics, STEP 2); resume fail-closed rate (must be ~0 outside real
deploy churn; any cluster is a C defect per ruling 5.1, post-C); the
snapshot cap headroom on iam-child-shaped walks (policy-scale facts).

## STEP 2 acceptance (for the implementing lane)

TDD, in this order, all hermetic (no live AWS):

1. Mid-walk source change: collect snapshot S, mutate the source,
   request later pages; assert byte-identical to S's split and a passing
   digest check. (Today's code fails this by recollecting: RED first.)
2. Restart semantics: serve page N, drop all process state, resume;
   assert page N+1 identical. Delete the snapshot file, resume; assert
   fail-closed retry-from-zero error, then page zero starts a new
   self-consistent walk with a new digest.
3. Pins: all existing paging tests pass unmodified (page bound,
   declared total, canonical order, digest keying).
4. Concurrency: two page-zero collects for one generation interleave;
   assert both walks self-consistent under their own cursors.
5. Cap: oversized snapshot construction trips terminal
   `snapshot-budget-exceeded`, never an over-budget page write.

Then the satellite implementation plus the G2 table per final instance:
single-collect wall (<=240 s), total walk (<=1200 s), zero drift shapes,
per-kind fact identity vs the 31732 baseline, zero throttle-caused leg
failures, per-walk provider call counts vs the recollect baseline
(expect ~pages x reduction), snapshot bytes, and peak per-call RSS vs
the 512 MiB budget. G2 also states whether the total walk fits one host
TTL or A' joins the final combination (ruling 5.2).

## Open questions

- Q1 (deploy): do all page calls of one walk execute on one filesystem
  where a satellite-local snapshot dir survives? If page calls can land
  on different pods/volumes, resume-after-death degrades to fail-closed
  plus new walk (still correct, never silently recollected), but the
  G2 serve pricing must be re-proven on that path. Owner: deploy/host
  lane confirmation. Safe default holds either way.
- Q2 (host): confirm the host retries a claim from page zero on the
  snapshot-miss error exactly as it does on today's drift error. The
  satellite-side shape is identical; host-side confirmation is
  coordinator-owned and does not block hermetic STEP 2.
- Q3 (host): confirm no failure-class allowlist needs updating for
  `snapshot-budget-exceeded` (precedent says no: `page-budget-exceeded`
  already flows).
- Q4 (parameters): snapshot TTL default (2 h proposed), snapshot dir
  default path, and whether the page-index sidecar is needed are STEP-2
  measurements, recorded here so the implementing lane does not
  re-derive them.
- Q5 (SSM): rides-C verdict awaits completed S-E (W-11172-se-complete);
  this record is SSM-agnostic by ruling design.
