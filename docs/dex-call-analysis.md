# Instruction call-site evidence — milestone 6

Submit an authenticated analysis job using:

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"dex_calls"}
```

Run the updated API and separate worker using [analysis jobs](analysis-jobs.md).
Poll the job and retrieve its /result. No dependency, migration, Android SDK or
training dataset is added. Existing adapters keep their versions and contracts.
GET /api/v1/analyzers advertises dex_calls separately.

## Evidence returned

The adapter retains identifier and network-string evidence, then traverses encoded
method lists and code-item instruction streams. Sensitive invoke findings include
caller and referenced target class, method, prototype descriptor and method index;
opcode; code-item offset; instruction offset in bytes and 16-bit code units; and
absolute byte offset inside the hashed DEX member. Evidence state is
decoded_invoke_instruction and analyst review remains required.

Ordinary and range invoke forms are supported. Payload blocks are skipped by
size so payload data is not mistaken for instructions. Opcode widths/names use
the pinned Androguard 4.1.4 mapping. Rules match exact class and method names
across overloads; argument semantics and API compatibility are not established.

A decoded invoke does not prove runtime execution or reachability. Linear sweep
can find instructions after return or in unreachable regions. Branch targets,
exception handlers, register types, argument types and full verifier constraints
are not validated. Virtual/interface references name the declared method, not a
resolved runtime dispatch target. Full DEX validation and Android installability
remain unverified. No malware verdict or risk score is produced.

## Coverage

Per-member instruction_analysis records tool versions, bounded issues, scan
counts, output_limited, reachability=not_analyzed and runtime_execution=not_observed.
A decoded stream is linear_sweep_decoded; no bodies yields no_method_bodies.
Overall member coverage is call_sites_decoded only when identifier output is
complete, at least one body decodes, and no tracked issue or finding cap occurs.
The job aggregates partial coverage; completed does not mean fully assessed.

Malformed streams discard call-site findings from that method; evidence from
other decoded methods remains. Missing code on concrete methods, invalid indexes,
registers/bounds, unsupported opcodes and limits create explicit issues.
Polymorphic/custom invokes remain unresolved with partial coverage rather than
being treated as ordinary method IDs. Scan counters include rejected attempts;
bodies_decoded and published call_sites identify successfully decoded output.

Existing archive/DEX/string/output/time bounds apply. New per-member defaults:
10,000 encoded methods, 10,000 encoded fields, 1,000,000 declared instruction
code units. Per-class aggregate member counts are also bounded. Retained issues
are capped at 100; call sites use max_dex_findings, with partial coverage when
capped. Configure backend/.env.example; submission snapshots these settings.
Subprocesses are not OS-level isolation. APK code is never executed and the
adapter makes no external requests. Native code, encrypted payloads, reflection
targets and cross-DEX reachability remain outside scope.

## Validation and references

Original synthetic code-item fixtures test ordinary/range invokes, unused
references, payload data, malformed streams, registers, code bounds, native flags,
output caps, unresolved invokes and a real worker/API result. They do not establish
Android installability or malware-detection accuracy. See
[database verification](postgresql-verification.md) for suite results.

Primary references: [DEX format](https://source.android.com/docs/core/runtime/dex-format)
and [Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode).
