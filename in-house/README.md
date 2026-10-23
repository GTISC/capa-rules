# GTISC in-house capa rules

## Frozen 293-ID feasibility pass

`coverage/windows-feasible-gap-review-v1.json` records an explicit decision for
every ID in the subsequent 293-ID gap. This pass implements supported variants
for 215 IDs and retains 78 open requirements for additional evidence or analysis
backends. The latter are not declared impossible and do not count as detectors.
The earlier 338/302/293 inventories below remain historical snapshots.

The implementation adds 154 static capa rules and 207 typed trace contracts
(203 new dynamic IDs; some IDs have multiple variants). The combined catalog
has 320 static IDs, 365 executable dynamic candidate IDs, and 396 IDs in their
union. These are detector-capacity counts, not executed-technique coverage.

Static rules include precise utility requests, target-specific artifact and
configuration references, and structural PE observations. The capa fork adds
bounded valid-section PE carving and uniform-overlay observations to its
native, PE-file, and .NET extractors. Tactic/technique presentation metadata is
pinned to the previously retrieved official MITRE pages under
`coverage/windows-feasible-attack-metadata-v1.json`.

Typed contracts bind actual argument roles, handles, process lifetimes,
symbolic states, byte counts, and content relationships. Additional parsers
handle LNK icon fields, referenced OOXML templates, a specified BMP pixel-LSB
variant, AD FS runtime configuration, native-x86 PEB/TLS/argument-buffer chains,
and network command/data flows. Utility launch requests do not prove utility
completion. Co-occurring static references do not prove runtime dataflow.

Mal-S2E owns the executable engine and its raw API field profiles. Captured
buffers are bounded to 1 MiB; text regex inputs to 32 KiB. Unsupported capture,
missing fields, and search-budget exhaustion never create evidence. The trace
catalog requires the updated engine; declaring a field does not install a guest
hook or recover an argument absent from an archived trace.

Rebuild the checked-in fixtures/catalogs with `tools/build_artifact_fixtures.py`
and `tools/build_feasible_detectors.py`. The harmless parsed DLL fixture is
built from `fixtures/feasible_payload.c` using MinGW `-shared -s` and
`-Wl,--no-insert-timestamp`. Run Mal-S2E's `test_feasible_detectors.py` and
`test_feasible_static_detectors.py` with this capa fork on `PYTHONPATH`.

Validation artifacts are under
`/mnt/data3/ding/pipeline-results/feasible-gap-detectors-20261016-v1/`.
Structural replay evaluates all 957 pinned originals, including 777 parseable
PEs, and finds two new static candidate IDs across 69 samples. It does not
replay all new function/basic-block rules. Replaying 372 archived journals
produces no new typed candidates or qualified runtime gains. Synthetic fixtures
are never imported as sample evidence.

These rules extend the upstream capa rule library without changing upstream
rule files. The GTISC/capa fork points its `rules` submodule at this fork so a
recursive checkout includes both upstream and in-house rules. Each in-house
rule needs a MITRE ATT&CK definition, a concrete feature rationale, and a
reproducible positive example. A capa match is a static capability observation,
not evidence that the API calls ran or that a technique completed.

`discovery/enumerate-local-groups-and-members.yml` maps T1069.001 when a
Windows function references both `NetLocalGroupEnum` and
`NetLocalGroupGetMembers`. The same function requirement narrows the upstream
parent-technique rules, but static analysis cannot prove success, call order,
or a local target. The benign source in `fixtures/local_group_capability.c`
demonstrates why this tag is not a malware verdict. The corresponding benign
PE fixture is included so capa's linter can verify the exact rule match. MITRE defines the technique
as finding local groups and users belonging to them:
https://attack.mitre.org/techniques/T1069/001/

To reproduce the positive match without running the fixture:

```sh
i686-w64-mingw32-gcc -O0 -fno-inline -o /tmp/local_group_capability.exe \
  in-house/fixtures/local_group_capability.c -lnetapi32
capa -r . -j /tmp/local_group_capability.exe > /tmp/local_group_capability.capa.json
```

Use a capa engine compatible with the current upstream rule syntax. For a pip
install, also pass `-s /path/to/capa/sigs` when signatures are not bundled.
The local smoke test used capa 9.4.0 and observed the T1069.001 tag at
`0x4015D0` for SHA-256
`157cfebd0658abeac72710fbd0184cf737d0c08041ecf58f1a5e158f5136e8d3`.

`api-sequences/windows-api-sequences-v1.json` is a separate catalog of four
ordered, successful Windows API sequences for T1003.002, T1021.002,
T1069.001, and T1018. It is **not capa YAML**: capa does not load or evaluate
it. Mal-S2E's `ci/identify_windows_behavior.py` invokes its trace evaluator
explicitly when given `--trace` and reports those IDs as observed API-sequence
candidates, separately from capa's static capabilities. Call success, order,
process scope, and object bindings are required by those rules, but trace
identity and completed effects need separate qualification.

`runtime-evidence-policy-v1.json` defines the admission boundary for future
dynamic rules. Reusable observations belong here as capa YAML when capa can
express the whole predicate, or in the ordered API-sequence catalog when
success, order, and argument bindings are required. Mal-S2E remains the owner
of sample identity, original-code or descendant provenance, completed OS
effects, and technique-completion predicates. Mal-Taxonomy mappings are
candidate hints only and must never supply an ATT&CK tag by rule-name fallback.

`runtime-telemetry-requirements-v1.json` is the machine-readable S2E backlog
for the next sample-backed detectors. It names the APIs, concrete arguments,
per-state call multiplicity, and remaining provenance or data-dependency
signals required for T1135, T1027.007, T1497.002, and T1496. Mal-S2E audits
actual lifecycle journals against this contract so hook work is driven by
measured trace gaps.

`discovery/enumerate-network-shares-dynamically.yml` supplies the dynamic
branch that the upstream mixed static/dynamic T1135 rule cannot satisfy from
S2E traces: the upstream rule depends on the static-only `contain loop` rule.
The in-house rule requires at least two successful `NetShareEnum` or
`WNetEnumResource` calls in one S2E state stream. Its fixtures cover both API
alternatives plus the single-call, split-state, and failed-repeat negatives
under `fixtures/dynamic/`. The match is an observation candidate and does not
add qualified runtime evidence by itself.

Reproduce the fixture validation with the GTISC capa checkout:

```sh
for case in network-share-positive network-share-positive-wnet \
  network-share-negative-single-call \
  network-share-negative-split-states network-share-negative-failed-repeat; do
  /path/to/capa/.venv/bin/python /path/to/capa/scripts/analyze-s2e.py \
    "in-house/fixtures/dynamic/$case" --rules . --out "/tmp/$case.json"
done
```

Three reachable gaps are intentionally still blocked from enabled rules:
T1027.007 needs the resolved-address binding and later invocation, and
T1497.002 needs concrete input state plus evidence that a comparison gated a
branch. T1496 needs a concrete mining workload or protocol exchange tied to
resource consumption. Adding API-name-only rules for these behaviors would
increase the mapping count while weakening the meaning of runtime evidence.

## Official-definition gap expansion

`coverage/windows-attack-gap-review-v1.json` retains the frozen 338-ID gap,
official MITRE technique URLs, website/definition hashes, short attributed
definition excerpts, design requirements, and per-ID admission decisions.
All 338 official technique pages were fetched successfully. The complete HTML
and extracted definitions are research artifacts outside this repository;
the checked-in excerpts and hashes pin the basis for the review.

This batch adds 36 capa rules for 36 previously unmapped IDs. All have static
function scope; 35 also have dynamic call/span scope. The LSASS/minidump rule
is static-only: references in one function cannot prove that a runtime dump
handle belongs to LSASS. The other rules cover credential-storage access,
raw-volume access, discovery, token-based process creation, Lua and AutoIt/
AutoHotkey capabilities, specific utility invocation forms, input synthesis,
sleep prevention, and defense configuration/clearing requests.

The remaining 302 definitions have `predicate_design_pending` dispositions,
with required context and a reason that API-only matching is insufficient.
These entries are design records, not enabled detectors. No tactic keyword,
family association, or automatic parent-technique roll-up creates a rule.
Some existing upstream rules use retired ATT&CK IDs; new rules use the active
IDs after checking the official definitions and replacement relationships.

Candidate scope is deliberately limited. Command rules recognize specific
direct process-launch forms; shell wrappers, alternate option orderings,
encoded commands, and payload execution require additional parsing and
qualification. A matching utility launch does not prove that its operation
succeeded. Registry/database opens do not prove credential extraction.
Static command strings assembled on the stack or decoded at runtime may be
invisible to the static extractor. Generic S2E argument values are not typed
target/handle bindings, and feature compatibility does not guarantee that a
current hook records every required argument.

Run the regression suite with the GTISC capa environment:

```sh
PYTHONPATH=/path/to/capa /path/to/capa/.venv/bin/python -m pytest -q \
  in-house/tests/test_official_gap_rules.py
```

`fixtures/official-gap-cases.json` contains hand-selected positive and near-
miss observation cases, including benign operations. The suite additionally
checks failed returns, unrelated-call arguments, and divergent-state
isolation through the actual S2E extractor and capa dynamic engine. With
`i686-w64-mingw32-gcc` available it compiles
`fixtures/official_gap_capabilities.c` and requires the full static analyzer
to match 35 new rules. Lua is covered by feature/dynamic fixtures, because
that PE does not link a Lua runtime. A second PE verifies function isolation.
The PE fixtures are analyzed without executing them; neither fixture creates
sample or runtime coverage credit.

Re-fetch the frozen gap's official source definitions:

```sh
python in-house/tools/fetch_attack_definitions.py \
  --audit /path/to/baseline-coverage-audit.json \
  --cache /path/to/research/mitre-html \
  --out /path/to/research/official-definitions.json
```

That batch grew the detector union from 136/474 to 172/474 IDs; the unmapped
gap decreased from 338 to 302. Its static capacity was 169/474 and S2E feature-
compatible dynamic capacity was 153/474. Replay of 372 existing journals
(78,781 successful calls) adds a T1006 observation candidate in 11 journals.
Those historical observations still require provenance and effect checks.
Only four of the 36 new rules have any of their required APIs represented in
the archived successful calls. No CreateProcess-family calls are recorded in
those journals, so the utility-launch rules need additional lifecycle
instrumentation before these archives can exercise them. Dynamic capacity
here measures extractor/rule feature compatibility, not deployed-hook
coverage.
Qualified runtime coverage remains 61/474; technique completion remains
1/474. The checks and their source digests are summarized in
`coverage/windows-attack-gap-validation-v1.json`.

## Bound trace prerequisites

`trace-contracts/windows-prerequisites-v1.json` adds nine executable contracts
for the next remaining IDs. These are interpreted by Mal-S2E's
`s2e_utils.trace_contracts`; capa does not evaluate this JSON catalog. The
contracts bind typed argument roles, successful return values, operation
order, resource handles, state/process lifetime, time windows, and optional
OS thread identity. Each contract links to the official definition and
declares an observation-candidate ceiling. The synthetic positive and negative
cases are in `fixtures/trace-prerequisite-cases.json`.

`coverage/windows-trace-prerequisite-models-v1.json` preserves the frozen
302-ID follow-up scope. Nine entries have admitted executable contracts;
293 remain requirements without detectors. It is generated by Mal-S2E's
`ci/audit_trace_prerequisites.py` and keeps prerequisite descriptions distinct
from executable stages. It also records their source definition hashes.

The newly supported cases are network-share file reads, PSReadLine history
deletion, new-token impersonation, file DACL updates, ROOT certificate-store
insertion, DDE execution, hidden file attributes, named NTFS stream writes,
and copies from a local file to a network-share destination. Binding the
wrong token/store/file, closing or reusing a handle, zero-byte I/O, unrelated
numeric fields, failed calls, and divergent states must remain negative or
insufficient-telemetry results. Ordinary administration can satisfy some
predicates; malicious intent and effect qualification remain separate.

With these contracts, detector capacity is 169 static IDs and 162 dynamic
IDs, with 181 in their union and a remaining gap of 293 IDs. The archived
372-journal replay produced no new matches from these contracts. Missing
named arguments, I/O handles, and transferred-byte counts remain concrete
instrumentation work; they are never synthesized from generic capacities.
Qualified runtime coverage remains 61/474.
