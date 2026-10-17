"""Native x86 PEB/TLS pointer-chain variants from actual remote-memory bytes."""

import copy
from pathlib import Path

import pefile

from feasible_relations import call, p, ref, stage


ROOT = Path(__file__).resolve().parents[1]
CASES = []


def offset(name, displacement):
    return {"ref": name, "add": displacement}


def read(identifier, address, count=None, bind=None):
    predicates = [p("process_handle", "eq", ref("remote")), p("address", "eq", address)]
    if count is not None:
        predicates.append(p("bytes_read", "eq", count))
    return stage(identifier, ["readprocessmemory"], predicates, bind)


def observe(address, data):
    return call(
        "ReadProcessMemory",
        process_handle=2401,
        address=address,
        bytes_read=len(data),
        buffer_hex=data.hex(),
    )


native = stage(
    "observe-native-x86",
    ["getnativesysteminfo"],
    [p("processor_architecture", "eq", 0)],
)
remote = stage(
    "resolve-remote-peb",
    ["ntqueryinformationprocess"],
    [
        p("information_class", "eq", 0),
        p("process_handle", "handle", True),
        p("peb_address", "handle", True),
        p("peb_address", "lt", 0x100000000),
        p("unique_process_id", "gt", 0),
        p("unique_process_id", "ne", {"event_field": "caller_pid"}),
    ],
    {"remote": "process_handle", "peb": "peb_address"},
)
base_calls = [
    call("GetNativeSystemInfo", processor_architecture=0),
    call(
        "NtQueryInformationProcess",
        process_handle=2401,
        information_class=0,
        peb_address=0x700000,
        unique_process_id=200,
    ),
]
closed = [{"apis": ["closehandle"], "field": "handle", "binding": "remote"}]
payload = (ROOT / "fixtures/local_group_capability.exe").read_bytes()
pe = pefile.PE(data=payload)
header = payload[: pe.OPTIONAL_HEADER.SizeOfHeaders]
tls_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress
assert tls_rva
pe.close()
tls_address = 0x400000 + tls_rva
tls = bytearray(24)
tls[12:16] = (0x401800).to_bytes(4, "little")
stages = [
    native,
    remote,
    read("read-main-image-pointer", offset("peb", 8), 4, {"image_base": "read_u32"}),
    read(
        "read-pe-tls-directory-rva", ref("image_base"), bind={"tls_rva": "pe_tls_rva"}
    ),
    read(
        "read-tls-directory",
        {"ref": "image_base", "add_ref": "tls_rva"},
        24,
        {"tls_address": "address", "old_callbacks": "tls_callbacks32"},
    ),
    stage(
        "replace-tls-callback-table-pointer",
        ["writeprocessmemory"],
        [
            p("process_handle", "eq", ref("remote")),
            p("address", "eq", offset("tls_address", 12)),
            p("bytes_written", "eq", 4),
            p("written_u32", "handle", True),
            p("written_u32", "ne", ref("old_callbacks")),
        ],
    ),
    stage(
        "request-thread-in-target",
        ["createremotethread"],
        [p("process_handle", "eq", ref("remote")), p("handle", "handle", True)],
    ),
]
calls = base_calls + [
    observe(0x700008, (0x400000).to_bytes(4, "little")),
    observe(0x400000, header),
    observe(tls_address, bytes(tls)),
    call(
        "WriteProcessMemory",
        process_handle=2401,
        address=tls_address + 12,
        bytes_written=4,
        buffer_hex=(0x402000).to_bytes(4, "little").hex(),
    ),
    call(
        "CreateRemoteThread", process_handle=2401, start_address=0x401000, handle=2501
    ),
]
negative = copy.deepcopy(calls)
negative[-2]["arguments"]["address"] += 4
CASES.append(
    dict(
        attack_id="T1055.005",
        name="replace a remote native-x86 TLS callback-table pointer",
        stages=stages,
        positive_calls=calls,
        negative_calls=[negative],
        same_thread=False,
        invalidate=closed,
        note="Binds a remote PID, native x86 PEB image pointer, actual PE TLS RVA, TLS descriptor, pointer replacement, and a target-thread request. Offset constants alone do not qualify. Actual payload/table validity, callback control transfer, sample provenance, and malicious intent remain unqualified.",
    )
)

original = "target.exe --secret".encode("utf-16le")
replacement = "target.exe --public".encode("utf-16le")
assert len(original) == len(replacement)
descriptor = (
    len(original).to_bytes(2, "little")
    + (len(original) + 2).to_bytes(2, "little")
    + (0x720000).to_bytes(4, "little")
)
stages = [
    native,
    remote,
    read("read-process-parameters", offset("peb", 0x10), 4, {"parameters": "read_u32"}),
    read(
        "read-command-line-descriptor",
        offset("parameters", 0x40),
        8,
        {"command_buffer": "unicode_buffer32", "command_length": "unicode_length32"},
    ),
    read(
        "read-original-arguments",
        ref("command_buffer"),
        ref("command_length"),
        {"original_arguments": "buffer_hex"},
    ),
    stage(
        "replace-recorded-process-arguments",
        ["writeprocessmemory"],
        [
            p("process_handle", "eq", ref("remote")),
            p("address", "eq", ref("command_buffer")),
            p("bytes_written", "eq", ref("command_length")),
            p("buffer_hex", "ne", ref("original_arguments")),
        ],
    ),
]
calls = base_calls + [
    observe(0x700010, (0x710000).to_bytes(4, "little")),
    observe(0x710040, descriptor),
    observe(0x720000, original),
    call(
        "WriteProcessMemory",
        process_handle=2401,
        address=0x720000,
        bytes_written=len(replacement),
        buffer_hex=replacement.hex(),
    ),
]
negative = copy.deepcopy(calls)
negative[-1]["arguments"]["address"] += 4
CASES.append(
    dict(
        attack_id="T1564.010",
        name="replace the bound remote process command-line buffer",
        stages=stages,
        positive_calls=calls,
        negative_calls=[negative],
        same_thread=False,
        invalidate=closed,
        note="Follows native-x86 PEB.ProcessParameters to the actual UNICODE_STRING command-line buffer, reads its old bytes, then observes a same-length replacement on that exact process/address. A generic remote write is insufficient. External process-creation baseline, display effect, and malicious concealment remain unqualified.",
    )
)
