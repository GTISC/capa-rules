"""Keep CRT cookie initialization separate from time-discovery candidates."""
from pathlib import Path

import capa.rules
from capa.features.address import AbsoluteVirtualAddress
from capa.features.insn import API, Number
import pytest


RULE = Path(__file__).resolve().parents[1] / "discovery/query-system-wall-clock-time.yml"
ENTROPY_APIS = {"GetSystemTimeAsFileTime", "GetCurrentProcessId", "GetCurrentThreadId",
                "GetTickCount", "QueryPerformanceCounter"}


def matches(names, cookie_constant=False):
    rule = capa.rules.Rule.from_yaml(RULE.read_text())
    features = {API(name): {AbsoluteVirtualAddress(0x401000)} for name in names}
    if cookie_constant:
        features[Number(0xBB40E64E)] = {AbsoluteVirtualAddress(0x401010)}
    return bool(rule.evaluate(features, short_circuit=False))


@pytest.mark.parametrize("api", ["GetSystemTime", "GetLocalTime", "GetSystemTimeAsFileTime",
                                 "GetSystemTimePreciseAsFileTime"])
def test_time_query_is_a_candidate(api):
    assert matches({api})


def test_complete_cookie_entropy_pattern_is_excluded():
    assert not matches(ENTROPY_APIS, cookie_constant=True)


@pytest.mark.parametrize("missing", sorted(ENTROPY_APIS - {"GetSystemTimeAsFileTime"}))
def test_partial_entropy_similarity_does_not_suppress_time_query(missing):
    assert matches(ENTROPY_APIS - {missing}, cookie_constant=True)


def test_entropy_apis_without_cookie_constant_are_still_candidates():
    assert matches(ENTROPY_APIS)
