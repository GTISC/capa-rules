# GTISC in-house capa rules

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
