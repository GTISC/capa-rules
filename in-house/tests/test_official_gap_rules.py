"""Exercise the actual capa and S2E engines against synthetic rule fixtures.

Run with the GTISC capa environment and PYTHONPATH pointing to that checkout.
No fixture is credited as real-sample runtime evidence.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import capa.rules
from capa.capabilities.dynamic import find_dynamic_capabilities
from capa.features.extractors.s2e import S2ELifecycleExtractor


ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "fixtures/official-gap-cases.json").read_text())["cases"]


@pytest.fixture(scope="session")
def rules():
    # Load the entire fork, so namespace/dependency integration is exercised.
    return capa.rules.get_rules([ROOT.parent], enable_cache=False)


def journal(tmp_path, calls, *, failed=False, split_states=False):
    rows = []
    for index, call in enumerate(calls, 1):
        state = index if split_states else 0
        for event in ("enter", "return"):
            row = {
                "schema": 1, "instance": 0, "state": state,
                "time_ns": index * 10 + (event == "return"),
                "entry_time_ns": index * 10, "pid": 100, "lifetime": 0,
                "depth": 0, "diagnostic_lineage": False, "call_id": index,
                "event": event, "api": call["api"],
                "module_hex": b"fixture.dll".hex(),
                "caller_pc": 0x401000, "callee_pc": 0x77001000,
                "path_hex": "", "value_hex": "", "requested": 0, "input_capacity": 0,
            }
            if "argument" in call:
                row["arguments"] = [{"name": "fixture_argument", "value": call["argument"]}]
            if event == "return":
                status_api = call["api"].startswith(("Net", "Wlan", "Reg", "lua_", "luaL_"))
                result = 5 if failed and status_api else 0 if failed or status_api else 1
                row.update(success=not failed, result=result, result_hex=hex(result), elapsed_ns=1)
            rows.append(row)
    path = tmp_path / "api-lifecycle.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return S2ELifecycleExtractor(tmp_path)


def matches(rules, extractor):
    return find_dynamic_capabilities(rules, extractor, disable_progress=True).matches


def feature_set(extractor):
    features = {}
    for process in extractor.get_processes():
        for thread in extractor.get_threads(process):
            for call in extractor.get_calls(process, thread):
                for feature, address in extractor.extract_call_features(process, thread, call):
                    features.setdefault(feature, set()).add(address)
    return features


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["attack_id"])
def test_official_positive_and_near_miss_predicates(case, rules, tmp_path):
    rule = rules[case["rule_name"]]
    for calls in case["positives"]:
        extractor = journal(tmp_path, calls)
        assert rule.evaluate(feature_set(extractor)), (case["attack_id"], calls)
        observed = case["rule_name"] in matches(rules, extractor)
        assert observed == (case["dynamic_scope"] != "unsupported"), (case["attack_id"], calls)
    for calls in case["negatives"]:
        extractor = journal(tmp_path, calls)
        assert not rule.evaluate(feature_set(extractor)), (case["attack_id"], calls)
        assert case["rule_name"] not in matches(rules, extractor)


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["attack_id"])
def test_failed_calls_never_add_dynamic_matches(case, rules, tmp_path):
    extractor = journal(tmp_path, case["positives"][0], failed=True)
    assert case["rule_name"] not in matches(rules, extractor)


@pytest.mark.parametrize(
    "case", [row for row in CASES if row["dynamic_scope"] == "span of calls"],
    ids=lambda row: row["attack_id"],
)
def test_multi_call_rules_do_not_combine_divergent_states(case, rules, tmp_path):
    extractor = journal(tmp_path, case["positives"][0], split_states=True)
    assert case["rule_name"] not in matches(rules, extractor)


@pytest.mark.parametrize(
    "case", [row for row in CASES if row["dynamic_scope"] == "call" and "argument" in row["positives"][0][0]],
    ids=lambda row: row["attack_id"],
)
def test_argument_on_an_unrelated_call_cannot_satisfy_rule(case, rules, tmp_path):
    original = case["positives"][0][0]
    calls = [{"api": original["api"]}, {"api": "GetTickCount", "argument": original["argument"]}]
    extractor = journal(tmp_path, calls)
    assert case["rule_name"] not in matches(rules, extractor)


def test_every_enabled_gap_rule_has_an_official_reference_and_fixture(rules):
    for case in CASES:
        rule = rules[case["rule_name"]]
        source = "https://attack.mitre.org/techniques/" + case["attack_id"].replace(".", "/") + "/"
        assert source in rule.meta["references"]
        assert len(case["negatives"]) >= 2


def test_review_retains_every_frozen_gap_and_keeps_pending_designs_disabled():
    review = json.loads((ROOT / "coverage/windows-attack-gap-review-v1.json").read_text())
    rows = review["techniques"]
    assert len(rows) == review["summary"]["baseline_missing_ids"] == 338
    assert len({row["attack_id"] for row in rows}) == 338
    enabled = {row["attack_id"] for row in rows if row["disposition"] == "implemented_candidate"}
    assert enabled == {row["attack_id"] for row in CASES}
    for row in rows:
        assert row["official_url"].startswith("https://attack.mitre.org/techniques/")
        assert len(row["website_sha256"]) == len(row["definition_sha256"]) == 64
        assert row["definition_requirement"] and row["required_observables"]
        if row["disposition"] == "predicate_design_pending":
            assert row["rule_paths"] == []
            assert row["reason_deferred"]


def test_full_static_pe_extraction_and_function_isolation(tmp_path):
    compiler = shutil.which("i686-w64-mingw32-gcc")
    if not compiler:
        pytest.skip("full static regression requires i686-w64-mingw32-gcc")
    binary = tmp_path / "capabilities.exe"
    subprocess.run([
        compiler, "-O0", "-fno-inline", str(ROOT / "fixtures/official_gap_capabilities.c"),
        "-o", str(binary), "-ldbghelp", "-lnetapi32", "-lwlanapi", "-lsetupapi",
        "-lmpr", "-ladvapi32", "-lfwpuclnt",
    ], check=True, capture_output=True)

    capa_root = Path(capa.rules.__file__).resolve().parents[2]

    def analyze(path):
        result = subprocess.run([
            sys.executable, "-m", "capa.main", "-q", "-j", "-r", str(ROOT.parent),
            "-s", str(capa_root / "sigs"), str(path),
        ], check=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    report = analyze(binary)
    targets = set(json.loads((ROOT / "fixtures/official-gap-static-expectations.json").read_text())["attack_ids"])
    expected = {case["rule_name"] for case in CASES if case["attack_id"] in targets}
    assert expected <= set(report["rules"])

    # LSASS and the dump API in distinct functions must not become a static
    # credential-dumping candidate just because both exist in one file.
    source = tmp_path / "isolated.c"
    source.write_text('''#include <windows.h>
#include <dbghelp.h>
static volatile int gate = 0;
static __attribute__((noinline)) void a(void) {
    MiniDumpWriteDump(NULL, 0, NULL, MiniDumpNormal, NULL, NULL, NULL);
}
static __attribute__((noinline)) void b(void) { OutputDebugStringA("lsass.exe"); }
int main(void) { if (gate) { a(); b(); } return 0; }
''')
    negative = tmp_path / "isolated.exe"
    subprocess.run([compiler, "-O0", "-fno-inline", str(source), "-o", str(negative), "-ldbghelp"],
                   check=True, capture_output=True)
    negative_report = analyze(negative)
    assert "reference lsass and process minidump in one function" not in negative_report["rules"]
    matched_new = {case["rule_name"] for case in CASES} & set(negative_report["rules"])
    # CRT startup can read the clock. Such a discovery capability is neither
    # malicious intent nor a false assertion of runtime execution.
    assert matched_new <= {"query system wall clock time"}
