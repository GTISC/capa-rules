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
