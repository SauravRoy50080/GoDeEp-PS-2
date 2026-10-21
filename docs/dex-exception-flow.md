# Exception-aware DEX control flow

Backend 0.32.0 adds the explicit `dex_exception_flow` 1.0.0 adapter. Its seven
connected additions are bounded try-region parsing, signed/unsigned handler decoding,
typed/catch-all resolution, instruction-boundary validation, exception-boundary
block splitting, conservative exception edges, and worker/catalog/report integration.
The existing `dex_control_flow` 1.0.0 normal-only adapter and other default analyzers
retain their existing semantics. No dependency or database migration is needed.

## Use through the existing analysis API

Queue an analysis for an uploaded sample:

```text
POST /api/v1/cases/{case_id}/analyses
```

```json
{"sample_id":"SAMPLE_UUID","adapter":"dex_exception_flow"}
```

Run the existing worker, fetch the result through the authenticated job endpoint,
and select the completed job when creating a forensic report. JSON reports and
existing passive HTML exports retain the complete emitted graph and source hashes.
The authenticated analyzer catalog advertises the new capability. Existing case
permissions apply; no user-supplied command or module is accepted. The worker verifies
the original APK hash and uses the configuration snapshotted when the job was queued.

## Parsing and evidence

The parser checks optional odd-code-unit zero padding, ordered non-overlapping
positive try intervals, data/byte bounds, exact handler-record offsets, bounded
32-bit signed and unsigned LEB128 values, catch type indices/class-descriptor shape,
and duplicate type indices within each handler. Typed catches preserve their order;
nonpositive signed handler sizes include a trailing catch-all. Legal one-to-five-byte
32-bit encodings are accepted without requiring shortest encoding. Format reference:
[Android DEX format](https://source.android.com/docs/core/runtime/dex-format).

Try starts and ends must align to decoded instruction boundaries. Handler targets
must be instruction starts, including those in unreferenced handler records. Operand
and payload targets are rejected. Ranges spanning payload data are conservatively
rejected. These are bounded syntactic checks, not a complete Android verifier.
Class hierarchy, Throwable ancestry, duplicate descriptors in the original type table,
catch shadowing and type dispatch are not resolved.

Each retained DEX member has `exception_flow.methods`. A method includes its identity,
code-item/instruction offsets, blocks, normal and exception edges, and `exception_tables`:

- regions: local ID, try-item byte offset, start/end code units, handler offset and ID.
- handlers: local ID, byte offset, referenced status and ordered catches.
- catches: type index/descriptor or catch-all, target code unit, order and encoded pair offset.
- table byte count/start and retained typed-catch count.

Code-unit offsets are relative to the method instruction array; byte offsets refer
to the uncompressed DEX member. The table start is immediately after instructions
and includes any required padding. Handler offsets are measured from the start of
the encoded handler list, including its size field. Block/region/handler IDs are
local to one method. Use `(job_id, member, method_index, local_id)` in a dashboard.
Hashes identify the original APK and each DEX member; forensic report metadata also
retains the source result hash.

## Graph semantics

Try starts, ends and every handler target split basic blocks, alongside existing
normal branch boundaries. Normal edges remain goto, branch_taken, switch_case and
fallthrough. Exception edges have `kind: exception_possible`, source/target blocks,
try/handler IDs, catch order/kind/type, protected block start/end, block byte offset,
and handler-entry byte offset. Their dispatch field explicitly says exception type
matching is unresolved. No instruction is falsely identified as the actual throw site.

Every protected block connects to every catch in its region, including blocks with
nonthrowing instructions, catch-alls and potentially shadowed catches. This is a
conservative overapproximation. Unreferenced handlers are retained/checked but add
no exception edges. Normal paths into handler code and disconnected code are retained.
`move-exception` placement and register rules are not verified; targets may omit it.
No feasible-path, entry reachability, actual exception, maliciousness, deobfuscation
success or runtime execution is inferred.

`normal_and_exception_targets_checked` means that retained syntactic structures and
targets passed these checks. Partial/failed coverage, decoder issues, flow issues
and `output_limited` remain explicit. Inspect all of them. Invalid or over-budget
methods publish no partial graph or metadata; earlier accepted methods remain.
An APK can have partial coverage even when the worker job completed successfully.
No-try methods retain their normal graph with an empty exception table.

## Bounds

Existing CFG budgets apply to attempted methods, per-method code units, and retained
blocks/edges across all ordinary DEX members. Normal and exception edges share one
edge budget. Additional configuration is snapshotted into each queued job:

| Environment setting | Default | Maximum | Scope |
|---|---|---|---|
| GODEEP_MAX_EXCEPTION_TRIES | 256 | 4096 | Retained regions per APK |
| GODEEP_MAX_EXCEPTION_HANDLERS | 512 | 4096 | Retained handler records per APK |
| GODEEP_MAX_EXCEPTION_CATCHES | 1024 | 8192 | Retained typed catches per APK |
| GODEEP_MAX_EXCEPTION_TABLE_BYTES | 32768 | 131072 | Table bytes per attempted method |

The first three minima are 1; table-byte minimum is 16. Catch-alls are additionally
bounded by handler count and emitted edge limits. Parsing checks declared counts
before iteration/allocation. Graph emission checks expansion against the remaining
edge budget before adding each block's catches. Range checks use bounded prefix
sums, and graph emission walks sorted regions/blocks without their Cartesian product.
Rejected methods do not consume retained metadata budgets, but consume the existing
attempt budget; later methods may still fit. Decoder, DEX byte/identifier, ZIP,
worker-time and result-byte bounds also remain in force.
`exception_flow_summary` records retained counts and configured budgets.

## Remaining limits

This does not fully validate map/section ownership or prevent overlapping unrelated
DEX data structures, verify checksums/signatures, validate every instruction/register/
type rule, resolve interprocedural dispatch, native code, reflection or dynamic
loading, or run APKs. Shared decoder limitations remain. No scoring or model changed.
Live sandbox validation/containment, broader runtime collectors and externally
validated ML remain separate work. These graphs provide reviewable evidence rather
than a malware verdict or an accuracy claim.
