# Bounded DEX normal control flow

Backend 0.27.0 adds `dex_control_flow` 1.0.0. It extracts syntactic normal-flow
basic blocks and edges for ordinary DEX code items after the shared bounded
linear decoder accepts the instruction stream. It does not execute an APK.

Queue the same way as other adapters:

`POST /api/v1/cases/{case_id}/analyses`

```json
{"sample_id":"<sample UUID>","adapter":"dex_control_flow"}
```

Run the existing analysis worker, then fetch the job/result through the usual
case-scoped analysis endpoints. Select the completed job in a forensic report to
retain its graph, input hash, adapter version, configuration and source result
hash. Existing HTML exports preserve the entire graph source record. No package,
frontend change or database migration is required.

## Scope and evidence

Each DEX member includes `normal_flow.methods`. Each retained method has its
identity, code-item offset, instruction-start byte offset, code-unit count,
entry block, basic blocks, normal edges, payload count and try-region count.
Block IDs such as `block:0` are local to one method in one DEX member. Use the
compound key `(job_id, member, method_index, block_id)` when building a UI.

Blocks record a start code unit, exclusive end code unit, absolute byte offset,
instruction count and terminal opcode/offset. Edges include source/target block,
branch instruction code unit, absolute byte offset and one of `goto`,
`branch_taken`, `fallthrough`, or `switch_case` (with a signed integer case value).
Code-unit offsets are relative to the method instruction start. Byte offsets are
relative to the uncompressed DEX member, not to the APK ZIP file. No instructions
are emitted for data payload contents.

Supported flow includes all three goto widths, two-register and zero-test
conditionals, packed and sparse switches, normal sequential fallthrough, returns
and throw termination. Switch target offsets are interpreted relative to the
switch opcode; switch tables are checked for kind, bounds and key ordering/range.
Fill-array-data references are checked against the corresponding payload kind;
array type/length compatibility is not checked. Goto/conditional targets and
normal successors must land on decoded instruction boundaries, never operands or
data. Forbidden zero offsets on short/16-bit gotos and conditionals are rejected;
goto/32 self-loops remain possible. Format reference:
[Android Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode).

## Coverage and limitations

`normal_targets_checked` means retained normal successors passed these syntactic
checks. It is not a full Android verifier result. Register/type checks remain
incomplete: tested branch registers and existing invoke checks are bounded, but
all operand/type rules, reserved bits, debug info, checksum/signature, class
relationships and try/handler structures are not validated. Exception edges are
not modeled. A method declaring try regions has
`partial_exception_flow_unmodeled`, and the enclosing DEX/APK remains partial.
Try-region count is a header observation, not verified exception-table metadata.

Disconnected instructions are retained as separate blocks when possible; entry
reachability is not computed, and paths may be infeasible. All decoded normal
successors are checked, including disconnected instructions. Unreachable padding
that appears to fall through into a payload may conservatively cause method
rejection. This is not a malware or corruption verdict. Interprocedural flow,
Android entrypoint modeling, virtual dispatch, reflection, native code, dynamic
loading, encrypted payloads and runtime execution remain unresolved. No risk
score or model inference changes.

If a method's stream/targets are malformed or its graph exceeds a budget, no
fragment of its graph is published. Earlier accepted methods remain available
with partial coverage and issues/limit flags. Shared decoder errors are in
`decoder.issues`; normal-flow errors are in `normal_flow.issues` (up to 100 per
member). Examine both. Overall worker time/byte limits can fail a job independently
of graph caps. Unsupported/malformed DEX members retain their existing failed
coverage. Original `dex_calls`, `dex_graph` and combined review default parsing
semantics/versions are unchanged; this adapter is explicitly selected.

## Bounds

| Setting | Default | Maximum | Scope |
|---|---:|---:|---|
| `GODEEP_MAX_CFG_METHODS` | 100 | 1000 | APK-wide attempted graph methods |
| `GODEEP_MAX_CFG_BLOCKS` | 2000 | 10000 | APK-wide retained blocks |
| `GODEEP_MAX_CFG_EDGES` | 4000 | 20000 | APK-wide retained normal edges |
| `GODEEP_MAX_CFG_CODE_UNITS` | 20000 | 100000 | Per method eligible for graph construction |

All settings require at least 1. Attempts count decoded bodies offered to the
flow builder, including rejected/over-budget methods, until the attempt cap is
reached. Existing raw DEX byte, file-count, identifier, string/prototype,
encoded-member and instruction-unit bounds still apply. Methods after the graph
attempt cap may still be decoded for coverage, but their graphs are omitted.

Switch case expansion is bounded before iterating/retaining its edges, including
when several switches share one payload. Block/edge allocation is capped during
construction; a too-large method is discarded as a unit. Later smaller methods
may still fit the remaining output budget. The result's `normal_flow_summary`
records total attempts, retained methods/blocks/edges and snapshotted budgets.
This remains an in-memory bounded worker, not an Android execution sandbox.
