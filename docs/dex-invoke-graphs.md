# Bounded DEX invoke-operand graphs

The `dex_graph` adapter 1.0.0 extends static triage to ordinary and range invokes,
including methods outside the existing sensitive-API allowlist. It extracts
caller/target method-ID operands from decoded instruction streams. This is not a
complete resolved call graph, control-flow graph or execution trace.

## Run

Queue through the existing authenticated case analysis API:

```json
{"sample_id": "SAMPLE-UUID", "adapter": "dex_graph"}
```

POST to `/api/v1/cases/{case_id}/analyses`, run the worker, poll the job and read
`/{job_id}/result`. The catalog now contains twelve registered adapters. Include
the completed graph job when creating a forensic report to snapshot its evidence
and limits. No new dependency, migration, external tool configuration or training
is needed. Restart API/worker after updating. Existing dex_calls/static/threat
adapter versions and default sensitive-only output semantics are unchanged.

## Result contract

Top-level provenance includes APK SHA-256, input size, adapter/version and bounded
per-DEX results. Each `dex_files` entry retains member path, member SHA-256, DEX
version/table counts, instruction-analysis issues and coverage, plus `invoke_graph`.
A failed/unsupported DEX remains visible rather than being silently omitted.

Graph nodes have local IDs such as `method:1`, method index, class descriptor,
method name, full prototype descriptor and observed roles (`caller` and/or
`target_operand`). Only methods participating in retained invokes appear. A target
node does not prove that a method body exists, that it belongs to packaged code,
or that runtime dispatch selects it.

Edges record caller/target local node IDs, invoke opcode, code-item offset,
absolute DEX byte offset, relative instruction byte/code-unit offsets and evidence
state `decoded_method_id_operand`. `sensitive_rule_id` preserves a match from the
existing API-name rule allowlist, or null for unlisted targets. Neither is proof
of runtime sensitive access. Repeated targets retain distinct instruction evidence.

IDs are scoped to one DEX member. Frontend graph keys should include analysis job
ID, member path and local node ID. Do not merge identical method indexes across
members. Cross-DEX aliases/definitions, duplicate classes, virtual/interface
implementation dispatch and reflection targets are not resolved. Overloads remain
distinct method-table identities with full descriptors; descriptor validity beyond
the bounded decoder is not fully verified.

## Bounds and coverage

`GODEEP_MAX_GRAPH_EDGES` defaults to 1,000 (range 1-5,000), and
`GODEEP_MAX_GRAPH_NODES` to 2,000 (range 1-10,000). These are totals shared by all
DEX members in one APK, not fresh limits for every member. Controls are recorded
in job configuration and graph_summary. Remaining budget is consumed in inspected
archive/method/instruction order, not by sensitivity or representativeness.

An edge is retained only if both endpoint nodes fit. Recursive/self operands share
one node. Node exhaustion omits the whole edge and reports partial coverage.
Exhausted invoke retention, unsupported/malformed code and upstream identifier
limits propagate as partial. Node/decoder output-limit flags and retained counts
are explicit. A method's pending edges are published only after its entire linear
instruction stream decodes; malformed streams discard pending graph evidence.
Payload bytes are skipped rather than interpreted as instructions.

Graph mode also caps assembled prototype length using max_dex_string_bytes, so
repeated parameter descriptors cannot grow an unbounded method signature. This
additional guard applies only to graph mode; existing sensitive-only output is
unchanged. Exceeded graph prototype bounds produce a partial method issue.

The parser still decodes under existing DEX/code-unit/method/time bounds. Existing
worker output-size limits apply to the complete JSON result; very long identifiers
or large graphs can exceed them and fail a job instead of returning clipped
identities. Tune operational bounds using controlled inputs; increasing graph
limits does not establish additional accuracy.

`graph_edges_extracted` / `selected_linear_sweep_complete` mean only that this
selected linear sweep completed within applicable bounds. No method bodies,
unsupported invokes or incomplete data remain partial. An empty graph is never
a clean verdict. Decoder attempted-instruction statistics can include attempts
in streams subsequently rejected; graph retained counts describe published edges.

## Interpretation and integration limits

Instructions following returns or on unreachable branches may still appear in a
linear sweep. Branches, exception handlers, full DEX semantics, Android
installability and method-ID runtime target selection are not validated. Custom
and polymorphic invokes remain explicit unresolved issues. There is no entrypoint
selection, path finding, taint/data flow, callback graph or runtime execution claim.

Existing original-byte verification, bounded subprocess worker, case permissions,
result hashing and forensic report creation apply. The comparison endpoint still
supports static_review/threat_review only. Graphs do not alter priority scoring,
library advisory claims or research classifier thresholds. No production inference
or live Android sandbox was added.

Controlled fixtures test sensitive/unlisted invokes, recursive node reuse,
ordinary/range opcodes, repeated targets, byte evidence, malformed methods,
payload handling, unreachable instructions, identifier-only data, global budgets
and real multidex worker/report/case integration. They are not a benchmark of
malware detection or full-program call-graph accuracy.
