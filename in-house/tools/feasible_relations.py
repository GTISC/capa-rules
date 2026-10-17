"""Concrete multi-operation variants requiring byte, object, or path binding."""

import copy


DOC = r"(?i)\A[A-Z]:\\Users\\[^\\]+\\Documents\\[^\r\n]+\.(?:docx?|pdf|txt|csv)\Z"
RAW_DISK = r"(?i)\A\\\\\.\\PhysicalDrive[0-9]+\Z"
CASES = []


def p(field, op, value):
    return {"field": field, "op": op, "value": value}


def ref(name):
    return {"ref": name}


def stage(identifier, apis, predicates, bind=None):
    return {"id": identifier, "apis": apis, "where": predicates, "bind": bind or {}}


def call(api, **arguments):
    return {"api": api, "arguments": arguments}


def opener(pattern, name="file", *, binding="file", path_binding=None):
    bindings = {binding: "handle"}
    if path_binding:
        bindings[path_binding] = "path"
    return stage(
        "open-" + name,
        ["createfile"],
        [p("path", "regex", pattern), p("handle", "handle", True)],
        bindings,
    )


def transfer(action, binding="file", *, buffer_binding=None, predicates=None):
    return stage(
        action + "-" + binding,
        [action + "file"],
        [p("handle", "eq", ref(binding)), p("bytes_transferred", "gt", 0)]
        + (predicates or []),
        {buffer_binding: "buffer_hex"} if buffer_binding else {},
    )


def close(binding="file"):
    return {
        "apis": ["createfile", "closehandle"],
        "field": "handle",
        "binding": binding,
    }


def relation(
    attack_id,
    name,
    stages,
    positive,
    negatives,
    note,
    invalidators=None,
    same_thread=False,
):
    CASES.append(
        dict(
            attack_id=attack_id,
            name=name,
            stages=stages,
            positive_calls=positive,
            negative_calls=negatives,
            note=note,
            invalidate=invalidators or [],
            same_thread=same_thread,
        )
    )


PLAIN = (b"This is a harmless document used for detector validation.\n" * 2).hex()
CIPHER = bytes(c ^ 0x5A for c in bytes.fromhex(PLAIN)).hex()
SOURCE = call("CreateFileW", path=r"C:\Users\lab\Documents\report.txt", handle=64)
READ = call(
    "ReadFile", handle=64, bytes_transferred=len(bytes.fromhex(PLAIN)), buffer_hex=PLAIN
)
SEEK = call("SetFilePointerEx", handle=64, distance=0, move_method=0)
WRITE = call(
    "WriteFile",
    handle=64,
    bytes_transferred=len(bytes.fromhex(CIPHER)),
    buffer_hex=CIPHER,
)
ENC = call("CryptEncrypt", input_hex=PLAIN, output_hex=CIPHER)

relation(
    "T1486",
    "encrypt and replace a bound user document",
    [
        opener(DOC),
        transfer("read", buffer_binding="plaintext"),
        stage(
            "encrypt-read-content",
            ["cryptencrypt"],
            [
                p("input_hex", "eq", ref("plaintext")),
                p("output_hex", "ne", ref("plaintext")),
            ],
            {"ciphertext": "output_hex"},
        ),
        stage(
            "seek-to-start",
            ["setfilepointerex"],
            [
                p("handle", "eq", ref("file")),
                p("distance", "eq", 0),
                p("move_method", "eq", 0),
            ],
        ),
        transfer("write", predicates=[p("buffer_hex", "eq", ref("ciphertext"))]),
    ],
    [SOURCE, READ, ENC, SEEK, WRITE],
    [
        [
            SOURCE,
            READ,
            call("CryptEncrypt", input_hex="00", output_hex=CIPHER),
            SEEK,
            WRITE,
        ],
        [
            SOURCE,
            READ,
            ENC,
            SEEK,
            call("WriteFile", handle=64, bytes_transferred=4, buffer_hex="01020304"),
        ],
    ],
    "Binds captured document bytes to successful encryption input/output and to replacement writes on the same file. Authorization, original sample identity, and impact beyond this file remain unproven.",
    [close()],
)

relation(
    "T1560.003",
    "archive collected document bytes using a custom XOR transform",
    [
        opener(DOC),
        transfer("read", buffer_binding="plaintext"),
        opener(
            r"(?i)\A[A-Z]:\\[^\r\n]+\.(?:dat|bin|arc)\Z",
            name="archive",
            binding="archive",
        ),
        transfer(
            "write",
            binding="archive",
            predicates=[p("buffer_hex", "xor_hex", ref("plaintext"))],
        ),
    ],
    [
        SOURCE,
        READ,
        call("CreateFileW", path=r"C:\stage\collection.arc", handle=80),
        call(
            "WriteFile",
            handle=80,
            bytes_transferred=len(bytes.fromhex(CIPHER)),
            buffer_hex=CIPHER,
        ),
    ],
    [
        [
            SOURCE,
            READ,
            call("CreateFileW", path=r"C:\stage\collection.arc", handle=80),
            call(
                "WriteFile",
                handle=80,
                bytes_transferred=len(bytes.fromhex(PLAIN)),
                buffer_hex=PLAIN,
            ),
        ]
    ],
    "Requires a nonzero constant-byte XOR relationship across at least 32 captured bytes read from a document and written to a separate archive handle. It does not infer exfiltration or adversary intent.",
    [close(), close("archive")],
)

relation(
    "T1485",
    "truncate a bound user document to zero length",
    [
        opener(DOC),
        stage(
            "seek-start",
            ["setfilepointerex"],
            [
                p("handle", "eq", ref("file")),
                p("distance", "eq", 0),
                p("move_method", "eq", 0),
            ],
        ),
        stage("truncate-document", ["setendoffile"], [p("handle", "eq", ref("file"))]),
    ],
    [SOURCE, SEEK, call("SetEndOfFile", handle=64)],
    [
        [
            SOURCE,
            call("SetFilePointerEx", handle=64, distance=100, move_method=0),
            call("SetEndOfFile", handle=64),
        ]
    ],
    "Observes a successful zero-offset truncation of a user-document handle. Its previous contents and unauthorized destructive intent require qualification.",
    [close()],
)

for attack_id, boot in [
    ("T1561", False),
    ("T1561.001", False),
    ("T1542", True),
    ("T1542.003", True),
]:
    payload = (
        (b"\xeb\x3c\x90" + b"\x90" * 507 + b"\x55\xaa").hex() if boot else "00" * 512
    )
    relation(
        attack_id,
        "replace a physical-drive boot sector"
        if boot
        else "zero a physical-drive initial sector",
        [
            opener(RAW_DISK),
            stage(
                "seek-initial-sector",
                ["setfilepointerex"],
                [
                    p("handle", "eq", ref("file")),
                    p("distance", "eq", 0),
                    p("move_method", "eq", 0),
                ],
            ),
            transfer(
                "write",
                predicates=[
                    p("bytes_transferred", "gt", 511),
                    p("buffer_hex", "boot_sector_hex" if boot else "zero_hex", True),
                ],
            ),
        ],
        [
            call("CreateFileW", path=r"\\.\PhysicalDrive0", handle=64),
            SEEK,
            call("WriteFile", handle=64, bytes_transferred=512, buffer_hex=payload),
        ],
        [
            [
                SOURCE,
                SEEK,
                call("WriteFile", handle=64, bytes_transferred=512, buffer_hex=payload),
            ],
            [
                call("CreateFileW", path=r"\\.\PhysicalDrive0", handle=64),
                SEEK,
                call("WriteFile", handle=64, bytes_transferred=1, buffer_hex=payload),
            ],
        ],
        "Requires actual captured sector bytes written at offset zero on a bound physical drive. A boot-code replacement is a pre-OS modification candidate; a zero-sector overwrite is a destruction candidate. Boot execution, malicious code, full-disk wiping, and device effects are not qualified.",
        [close()],
    )

DRIVE = stage(
    "classify-removable-drive",
    ["getdrivetype"],
    [p("drive_type", "eq", 2), p("root_path", "regex", r"(?i)\A[A-Z]:\\\Z")],
    {"volume": "root_path"},
)
drive_call = {**call("GetDriveTypeW", root_path="E:\\"), "result": 2}
removable_open = opener(r"(?i)\A[A-Z]:\\[^\r\n]+", name="removable", binding="media")
removable_open["where"].append(p("path", "same_volume", ref("volume")))
relation(
    "T1025",
    "read content from a classified removable volume",
    [DRIVE, removable_open, transfer("read", binding="media")],
    [
        drive_call,
        call("CreateFileW", path=r"E:\documents\report.txt", handle=80),
        call("ReadFile", handle=80, bytes_transferred=8),
    ],
    [
        [
            {**drive_call, "result": 3},
            call("CreateFileW", path=r"E:\documents\report.txt", handle=80),
            call("ReadFile", handle=80, bytes_transferred=8),
        ],
        [
            drive_call,
            call("CreateFileW", path=r"F:\documents\report.txt", handle=80),
            call("ReadFile", handle=80, bytes_transferred=8),
        ],
    ],
    "Binds a successful nonempty read to the exact drive reported DRIVE_REMOVABLE; it does not assume every non-system drive is removable.",
    [close("media")],
)
relation(
    "T1052",
    "copy collected document bytes onto removable media",
    [
        opener(DOC),
        transfer("read", buffer_binding="collected"),
        DRIVE,
        removable_open,
        transfer(
            "write",
            binding="media",
            predicates=[p("buffer_hex", "eq", ref("collected"))],
        ),
    ],
    [
        SOURCE,
        READ,
        drive_call,
        call("CreateFileW", path=r"E:\stage\report.txt", handle=80),
        call(
            "WriteFile",
            handle=80,
            bytes_transferred=len(bytes.fromhex(PLAIN)),
            buffer_hex=PLAIN,
        ),
    ],
    [
        [
            SOURCE,
            READ,
            drive_call,
            call("CreateFileW", path=r"F:\stage\report.txt", handle=80),
            call(
                "WriteFile",
                handle=80,
                bytes_transferred=len(bytes.fromhex(PLAIN)),
                buffer_hex=PLAIN,
            ),
        ]
    ],
    "Requires captured user-document bytes to be written to the same classified removable volume. Removal of the medium and unauthorized disclosure remain unproven.",
    [close(), close("media")],
)

descriptor = bytearray(36)
descriptor[:4] = (36).to_bytes(4, "little")
descriptor[4:8] = (36).to_bytes(4, "little")
descriptor[28:32] = (7).to_bytes(4, "little")
usb_probe = call(
    "DeviceIoControl",
    device_handle=96,
    io_control_code=0x2D1400,
    input_hex="00" * 8,
    output_hex=descriptor.hex(),
    bytes_returned=36,
)
usb_open = opener(
    r"(?i)\A\\\\\.\\[A-Z]:\Z",
    name="usb-volume",
    binding="device",
    path_binding="volume",
)
usb_classify = stage(
    "query-usb-bus",
    ["deviceiocontrol"],
    [
        p("device_handle", "eq", ref("device")),
        p("io_control_code", "eq", 0x2D1400),
        p("storage_bus_type", "eq", 7),
    ],
)
relation(
    "T1052.001",
    "copy collected document bytes to a USB-classified volume",
    [
        opener(DOC),
        transfer("read", buffer_binding="collected"),
        usb_open,
        usb_classify,
        removable_open,
        transfer(
            "write",
            binding="media",
            predicates=[p("buffer_hex", "eq", ref("collected"))],
        ),
    ],
    [
        SOURCE,
        READ,
        call("CreateFileW", path=r"\\.\E:", handle=96),
        usb_probe,
        call("CreateFileW", path=r"E:\stage\report.txt", handle=80),
        call(
            "WriteFile",
            handle=80,
            bytes_transferred=len(bytes.fromhex(PLAIN)),
            buffer_hex=PLAIN,
        ),
    ],
    [
        [
            SOURCE,
            READ,
            call("CreateFileW", path=r"\\.\E:", handle=96),
            {
                **usb_probe,
                "arguments": {**usb_probe["arguments"], "output_hex": bytes(36).hex()},
            },
            call("CreateFileW", path=r"E:\stage\report.txt", handle=80),
            call(
                "WriteFile",
                handle=80,
                bytes_transferred=len(bytes.fromhex(PLAIN)),
                buffer_hex=PLAIN,
            ),
        ]
    ],
    "Derives BusTypeUsb from a captured STORAGE_DEVICE_DESCRIPTOR response for the bound volume; DRIVE_REMOVABLE alone never establishes USB. Requires document-byte equality at the media write.",
    [close(), close("media"), close("device")],
)

module_path = r"C:\stage\sample.exe"
module_call = {
    **call(
        "GetModuleFileNameW",
        module_handle=0,
        module_path=module_path,
        buffer_capacity=260,
    ),
    "result": len(module_path),
}
self_image = stage(
    "identify-current-image",
    ["getmodulefilename"],
    [p("module_handle", "eq", 0), p("module_path", "local_path", True)],
    {"image": "module_path"},
)
relation(
    "T1091",
    "replicate the current image onto a classified removable drive",
    [
        self_image,
        DRIVE,
        stage(
            "copy-current-image",
            ["copyfile"],
            [
                p("source_path", "eq", ref("image")),
                p("destination_path", "same_volume", ref("volume")),
            ],
        ),
    ],
    [
        module_call,
        drive_call,
        call("CopyFileW", source_path=module_path, destination_path=r"E:\sample.exe"),
    ],
    [
        [
            module_call,
            drive_call,
            call(
                "CopyFileW",
                source_path=r"C:\unrelated.exe",
                destination_path=r"E:\sample.exe",
            ),
        ]
    ],
    "Binds the current executable image to the source of a removable-drive copy. It does not infer autorun or actual infection of a second host.",
)
relation(
    "T1070.010",
    "relocate the current executable image",
    [
        self_image,
        stage(
            "move-current-image",
            ["movefile"],
            [
                p("source_path", "eq", ref("image")),
                p("destination_path", "local_path", True),
                p("destination_path", "ne", ref("image")),
            ],
        ),
    ],
    [
        module_call,
        call(
            "MoveFileW",
            source_path=module_path,
            destination_path=r"C:\other\sample.exe",
        ),
    ],
    [
        [
            module_call,
            call(
                "MoveFileW",
                source_path=r"C:\unrelated.exe",
                destination_path=r"C:\other\sample.exe",
            ),
        ]
    ],
    "Requires a successful relocation of the actual current executable path; original malware identity and evasion intent remain unproven.",
)
relation(
    "T1036.003",
    "copy a system utility under a different executable name",
    [
        stage(
            "copy-and-rename-known-utility",
            ["copyfile", "movefile"],
            [
                p(
                    "source_path",
                    "regex",
                    r"(?i)\AC:\\Windows\\System32\\(?:certutil|bitsadmin|rundll32|regsvr32)\.exe\Z",
                ),
                p(
                    "destination_path",
                    "regex",
                    r"(?i)\AC:\\Users\\[^\\]+\\[^\r\n]+\.exe\Z",
                ),
            ],
            {"original": "source_path", "renamed": "destination_path"},
        ),
        stage(
            "launch-renamed-utility",
            ["createprocess"],
            [
                p("application_name", "eq", ref("renamed")),
                p("application_name", "different_basename", ref("original")),
            ],
        ),
    ],
    [
        call(
            "CopyFileW",
            source_path=r"C:\Windows\System32\certutil.exe",
            destination_path=r"C:\Users\lab\Downloads\update.exe",
        ),
        call(
            "CreateProcessW",
            application_name=r"C:\Users\lab\Downloads\update.exe",
            command_line="update.exe -?",
        ),
    ],
    [
        [
            call(
                "CopyFileW",
                source_path=r"C:\Windows\System32\certutil.exe",
                destination_path=r"C:\Users\lab\Downloads\certutil.exe",
            ),
            call(
                "CreateProcessW",
                application_name=r"C:\Users\lab\Downloads\certutil.exe",
                command_line="certutil.exe -?",
            ),
        ]
    ],
    "Observes copying a known system-utility path and launching the destination under a different basename. Signature/publisher authenticity and malicious intent still require qualification.",
)

exclusion_open = stage(
    "open-defender-path-exclusions",
    ["regopenkeyex"],
    [
        p(
            "key_path",
            "regex",
            r"(?i)\A(?:HKLM|HKEY_LOCAL_MACHINE)\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\Z",
        ),
        p("key_handle", "handle", True),
    ],
    {"exclusions": "key_handle"},
)
relation(
    "T1564.012",
    "write inside a previously observed antivirus path exclusion",
    [
        exclusion_open,
        stage(
            "read-active-exclusion",
            ["regqueryvalueex"],
            [
                p("key_handle", "eq", ref("exclusions")),
                p("value_name", "local_path", True),
                p("value_type", "eq", 4),
                p("value_data", "eq", 0),
            ],
            {"excluded_path": "value_name"},
        ),
        stage(
            "open-excluded-target",
            ["createfile"],
            [
                p("path", "within_path", ref("excluded_path")),
                p("handle", "handle", True),
            ],
            {"file": "handle"},
        ),
        transfer("write"),
    ],
    [
        call(
            "RegOpenKeyExW",
            key_path=r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            key_handle=128,
        ),
        call(
            "RegQueryValueExW",
            key_handle=128,
            value_name=r"C:\excluded",
            value_type=4,
            value_data=0,
        ),
        call("CreateFileW", path=r"C:\excluded\payload.bin", handle=64),
        call("WriteFile", handle=64, bytes_transferred=8),
    ],
    [
        [
            call(
                "RegOpenKeyExW",
                key_path=r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                key_handle=128,
            ),
            call(
                "RegQueryValueExW",
                key_handle=128,
                value_name=r"C:\excluded",
                value_type=4,
                value_data=0,
            ),
            call("CreateFileW", path=r"C:\excluded-sibling\payload.bin", handle=64),
            call("WriteFile", handle=64, bytes_transferred=8),
        ]
    ],
    "Binds a write to a boundary-checked path read from an existing Defender exclusion setting; adding an exclusion is a separate behavior. Effective policy, reparse-point resolution, and payload identity require qualification.",
    [
        close(),
        {
            "apis": ["regclosekey", "regopenkeyex", "regcreatekeyex"],
            "field": "key_handle",
            "binding": "exclusions",
        },
    ],
)

reg_close = [
    {
        "apis": ["regclosekey", "regopenkeyex", "regcreatekeyex"],
        "field": "key_handle",
        "binding": "key",
    }
]
relation(
    "T1027.011",
    "store a parsed executable payload in a registry binary value",
    [
        stage(
            "open-storage-key",
            ["regopenkeyex", "regcreatekeyex"],
            [
                p(
                    "key_path",
                    "regex",
                    r"(?i)\A(?:HKCU|HKEY_CURRENT_USER)\\Software\\[^\r\n]+\Z",
                ),
                p("key_handle", "handle", True),
            ],
            {"key": "key_handle"},
        ),
        stage(
            "store-executable-bytes",
            ["regsetvalueex"],
            [
                p("key_handle", "eq", ref("key")),
                p("value_name", "regex", r"\S"),
                p("value_type", "eq", 3),
                p("value_size", "gt", 0),
                p("value_data", "pe_hex", True),
            ],
        ),
    ],
    [
        call("RegCreateKeyExW", key_path=r"HKCU\Software\Lab", key_handle=128),
        call(
            "RegSetValueExW",
            key_handle=128,
            value_name="Cache",
            value_type=3,
            value_data="@fixture:local_group_capability.exe",
            value_size="@fixture_size",
        ),
    ],
    [
        [
            call("RegCreateKeyExW", key_path=r"HKCU\Software\Lab", key_handle=128),
            call(
                "RegSetValueExW",
                key_handle=128,
                value_name="Cache",
                value_type=3,
                value_data="4d5a",
                value_size=2,
            ),
        ]
    ],
    "Requires a complete structurally parsed PE payload stored as REG_BINARY on the bound key. It observes fileless payload storage, not its subsequent execution or maliciousness.",
    reg_close,
)

service_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LabService"
relation(
    "T1036.004",
    "give a user-path service a Windows service display identity",
    [
        stage(
            "open-service-configuration",
            ["regopenkeyex", "regcreatekeyex"],
            [
                p(
                    "key_path",
                    "regex",
                    r"(?i)\A(?:HKLM|HKEY_LOCAL_MACHINE)\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+\Z",
                ),
                p("key_handle", "handle", True),
            ],
            {"key": "key_handle"},
        ),
        stage(
            "set-user-path-image",
            ["regsetvalueex"],
            [
                p("key_handle", "eq", ref("key")),
                p("value_name", "regex", r"(?i)\AImagePath\Z"),
                p("value_type", "in", [1, 2]),
                p("value_data", "regex", r'(?i)\A"?C:\\Users\\[^\r\n]+\.exe"?\Z'),
            ],
        ),
        stage(
            "set-system-looking-display-name",
            ["regsetvalueex"],
            [
                p("key_handle", "eq", ref("key")),
                p("value_name", "regex", r"(?i)\ADisplayName\Z"),
                p("value_type", "eq", 1),
                p(
                    "value_data",
                    "in",
                    ["Windows Update", "Windows Defender", "Windows Security Service"],
                ),
            ],
        ),
    ],
    [
        call("RegOpenKeyExW", key_path=service_key, key_handle=128),
        call(
            "RegSetValueExW",
            key_handle=128,
            value_name="ImagePath",
            value_type=1,
            value_data=r"C:\Users\lab\Downloads\service.exe",
        ),
        call(
            "RegSetValueExW",
            key_handle=128,
            value_name="DisplayName",
            value_type=1,
            value_data="Windows Update",
        ),
    ],
    [
        [
            call("RegOpenKeyExW", key_path=service_key, key_handle=128),
            call(
                "RegSetValueExW",
                key_handle=128,
                value_name="ImagePath",
                value_type=1,
                value_data=r"C:\Users\lab\Downloads\service.exe",
            ),
            call(
                "RegSetValueExW",
                key_handle=999,
                value_name="DisplayName",
                value_type=1,
                value_data="Windows Update",
            ),
        ]
    ],
    "Binds a system-looking display name to a service image configured under a user directory. It does not infer publisher trust, service execution, or malicious intent.",
    reg_close,
)

verify_args = dict(
    file_path=r"C:\Windows\System32\lab.exe",
    union_choice=1,
    action_guid="00aac56b-cd44-11d0-8cc2-00c04fc295ee",
)
verify_stage = stage(
    "observe-signature-digest-mismatch",
    ["winverifytrust"],
    [
        p("file_path", "regex", r"(?i)\A[A-Z]:\\[^\r\n]+\.(?:exe|dll|sys)\Z"),
        p("union_choice", "eq", 1),
        p("action_guid", "regex", r"(?i)\A00aac56b-cd44-11d0-8cc2-00c04fc295ee\Z"),
        p("verification_status", "eq", 0x80096010),
    ],
)
verify_stage["observe_return_status"] = True
relation(
    "T1036.001",
    "observe a file Authenticode digest mismatch",
    [verify_stage],
    [{**call("WinVerifyTrust", **verify_args), "result": 0x80096010}],
    [
        [{**call("WinVerifyTrust", **verify_args), "result": 0}],
        [{**call("WinVerifyTrust", **verify_args), "result": 0x800B0109}],
    ],
    "Observes TRUST_E_BAD_DIGEST for the exact Authenticode file verification action. An untrusted chain or an arbitrary failed API does not satisfy this predicate. Malicious masquerading intent remains unproven.",
)
before = copy.deepcopy(verify_stage)
before.update(id="observe-trusted-host-binary", bind={"host_binary": "file_path"})
before["where"][0] = p(
    "file_path", "regex", r"(?i)\AC:\\Windows\\System32\\[^\\]+\.(?:exe|dll)\Z"
)
before["where"][-1] = p("verification_status", "eq", 0)
after = copy.deepcopy(verify_stage)
after["where"][0] = p("file_path", "eq", ref("host_binary"))
relation(
    "T1554",
    "modify a previously trusted host binary and observe a digest mismatch",
    [
        before,
        stage(
            "open-trusted-host-binary",
            ["createfile"],
            [p("path", "eq", ref("host_binary")), p("handle", "handle", True)],
            {"file": "handle"},
        ),
        transfer("write"),
        after,
    ],
    [
        {**call("WinVerifyTrust", **verify_args), "result": 0},
        call("CreateFileW", path=verify_args["file_path"], handle=64),
        call("WriteFile", handle=64, bytes_transferred=8),
        {**call("WinVerifyTrust", **verify_args), "result": 0x80096010},
    ],
    [
        [
            {**call("WinVerifyTrust", **verify_args), "result": 0x800B0109},
            call("CreateFileW", path=verify_args["file_path"], handle=64),
            call("WriteFile", handle=64, bytes_transferred=8),
            {**call("WinVerifyTrust", **verify_args), "result": 0x80096010},
        ]
    ],
    "Requires a trusted host binary, a bound modification, and a subsequent bad-digest result on the same path. Actual object continuity, legitimate update exclusion, sample identity, and malicious intent require qualification.",
    [close()],
)

uac_path = r"HKCU\Software\Classes\ms-settings\Shell\Open\command"
relation(
    "T1548",
    "request elevation through a user-controlled auto-elevation command",
    [
        stage(
            "open-auto-elevation-command",
            ["regopenkeyex", "regcreatekeyex"],
            [
                p(
                    "key_path",
                    "regex",
                    r"(?i)\A(?:HKCU|HKEY_CURRENT_USER)\\Software\\Classes\\ms-settings\\Shell\\Open\\command\Z",
                ),
                p("key_handle", "handle", True),
            ],
            {"key": "key_handle"},
        ),
        stage(
            "set-empty-delegate",
            ["regsetvalueex"],
            [
                p("key_handle", "eq", ref("key")),
                p("value_name", "eq", "DelegateExecute"),
                p("value_type", "eq", 1),
                p("value_data", "eq", ""),
            ],
        ),
        stage(
            "set-payload-command",
            ["regsetvalueex"],
            [
                p("key_handle", "eq", ref("key")),
                p("value_name", "eq", ""),
                p("value_type", "eq", 1),
                p("value_data", "regex", r"(?i)\A[A-Z]:\\[^\r\n]+\.exe\Z"),
            ],
        ),
        stage(
            "launch-auto-elevation-helper",
            ["createprocess"],
            [
                p("application_name", "eq", ""),
                p(
                    "command_line",
                    "regex",
                    r"(?i)\AC:\\Windows\\System32\\fodhelper\.exe\Z",
                ),
            ],
        ),
    ],
    [
        call("RegCreateKeyExW", key_path=uac_path, key_handle=128),
        call(
            "RegSetValueExW",
            key_handle=128,
            value_name="DelegateExecute",
            value_type=1,
            value_data="",
        ),
        call(
            "RegSetValueExW",
            key_handle=128,
            value_name="",
            value_type=1,
            value_data=r"C:\stage\payload.exe",
        ),
        call(
            "CreateProcessW",
            application_name="",
            command_line=r"C:\Windows\System32\fodhelper.exe",
        ),
    ],
    [
        [
            call("RegCreateKeyExW", key_path=uac_path, key_handle=128),
            call(
                "RegSetValueExW",
                key_handle=128,
                value_name="DelegateExecute",
                value_type=1,
                value_data="",
            ),
            call(
                "RegSetValueExW",
                key_handle=999,
                value_name="",
                value_type=1,
                value_data=r"C:\stage\payload.exe",
            ),
            call(
                "CreateProcessW",
                application_name="",
                command_line=r"C:\Windows\System32\fodhelper.exe",
            ),
        ]
    ],
    "A direct UAC-bypass implementation predicate for the elevation-control parent technique. Actual elevated token, child payload execution, patched-system behavior, and malicious intent remain unproven.",
    reg_close,
)

default_sid = b"\x01\x05\0\0\0\0\0\x05" + b"".join(
    n.to_bytes(4, "little") for n in [21, 1, 2, 3, 500]
)
relation(
    "T1078.001",
    "authenticate and resolve a built-in account SID",
    [
        stage(
            "authenticate-account",
            ["logonuser"],
            [
                p("username", "regex", r"\S"),
                p("logon_type", "in", [2, 3, 4, 5, 7, 8]),
                p("token_handle", "handle", True),
            ],
            {"token": "token_handle"},
        ),
        stage(
            "resolve-built-in-account",
            ["gettokeninformation"],
            [
                p("token_handle", "eq", ref("token")),
                p("information_class", "eq", 1),
                p("account_rid", "in", [500, 501]),
            ],
        ),
    ],
    [
        call("LogonUserW", username="Administrator", logon_type=2, token_handle=64),
        call(
            "GetTokenInformation",
            token_handle=64,
            information_class=1,
            user_sid_hex=default_sid.hex(),
        ),
    ],
    [
        [
            call("LogonUserW", username="Administrator", logon_type=2, token_handle=64),
            call(
                "GetTokenInformation",
                token_handle=64,
                information_class=1,
                user_sid_hex=(default_sid[:-4] + (1000).to_bytes(4, "little")).hex(),
            ),
        ],
        [
            call("LogonUserW", username="Administrator", logon_type=9, token_handle=64),
            call(
                "GetTokenInformation",
                token_handle=64,
                information_class=1,
                user_sid_hex=default_sid.hex(),
            ),
        ],
    ],
    "Requires successful logon and a bound TokenUser SID with account-domain prefix and built-in Administrator/Guest RID. A username or successful authentication alone does not establish a default account. Unauthorized use is not inferred.",
    [{"apis": ["closehandle"], "field": "handle", "binding": "token"}],
)

dll_path = r"C:\Users\lab\Downloads\version.dll"
dll_open = opener(
    r"(?i)\AC:\\Users\\[^\\]+\\Downloads\\version\.dll\Z", path_binding="dll_path"
)
dll_open["bind"]["dll_directory"] = "parent_directory"
relation(
    "T1574.001",
    "plant and resolve a system-named DLL through a modified DLL directory",
    [
        dll_open,
        transfer("write", predicates=[p("buffer_hex", "dll_hex", True)]),
        stage(
            "select-dll-search-directory",
            ["setdlldirectory"],
            [p("directory", "eq", ref("dll_directory"))],
        ),
        stage(
            "load-unqualified-system-dll-name",
            ["loadlibrary"],
            [p("requested_path", "regex", r"(?i)\Aversion\.dll\Z")],
            {"module": "handle"},
        ),
        stage(
            "resolve-loaded-payload-path",
            ["getmodulefilename"],
            [
                p("module_handle", "eq", ref("module")),
                p("module_path", "eq", ref("dll_path")),
            ],
        ),
    ],
    [
        call("CreateFileW", path=dll_path, handle=64),
        call(
            "WriteFile",
            handle=64,
            bytes_transferred="@fixture_size",
            buffer_hex="@fixture:feasible_payload.dll",
        ),
        call("SetDllDirectoryW", directory=r"C:\Users\lab\Downloads"),
        call("LoadLibraryW", requested_path="version.dll", handle=2101),
        {
            **call(
                "GetModuleFileNameW",
                module_handle=2101,
                module_path=dll_path,
                buffer_capacity=260,
            ),
            "result": len(dll_path),
        },
    ],
    [
        [
            call("CreateFileW", path=dll_path, handle=64),
            call(
                "WriteFile",
                handle=64,
                bytes_transferred="@fixture_size",
                buffer_hex="@fixture:feasible_payload.dll",
            ),
            call("SetDllDirectoryW", directory=r"C:\Users\lab\Downloads"),
            call("LoadLibraryW", requested_path="version.dll", handle=2101),
            {
                **call(
                    "GetModuleFileNameW",
                    module_handle=2101,
                    module_path=r"C:\Windows\System32\version.dll",
                    buffer_capacity=260,
                ),
                "result": len(r"C:\Windows\System32\version.dll"),
            },
        ]
    ],
    "Requires parsed DLL bytes, search-directory modification, an unqualified system-DLL name, and actual resolved-module path equality. Publisher identity, expected dependency, loader causality, and malicious code execution remain unqualified.",
    [close()],
)

exe_path = r"C:\Users\lab\Downloads\updater.exe"
exe_open = opener(
    r"(?i)\AC:\\Users\\[^\\]+\\Downloads\\updater\.exe\Z", path_binding="executable"
)
exe_open["bind"]["executable_directory"] = "parent_directory"
relation(
    "T1574.008",
    "resolve an unqualified executable inside a modified PATH directory",
    [
        exe_open,
        transfer("write", predicates=[p("buffer_hex", "pe_hex", True)]),
        stage(
            "change-path-directory",
            ["setenvironmentvariable"],
            [
                p("variable_name", "regex", r"(?i)\APATH\Z"),
                p("variable_value", "eq", ref("executable_directory")),
            ],
        ),
        stage(
            "request-unqualified-executable",
            ["createprocess"],
            [
                p("application_name", "eq", ""),
                p("command_line", "regex", r"(?i)\Aupdater\.exe(?: [^\r\n]*)?\Z"),
                p("process_handle", "handle", True),
            ],
            {"child": "process_handle"},
        ),
        stage(
            "resolve-actual-child-image",
            ["queryfullprocessimagename"],
            [
                p("process_handle", "eq", ref("child")),
                p("flags", "eq", 0),
                p("image_path", "eq", ref("executable")),
            ],
        ),
    ],
    [
        call("CreateFileW", path=exe_path, handle=64),
        call(
            "WriteFile",
            handle=64,
            bytes_transferred="@fixture_size",
            buffer_hex="@fixture:local_group_capability.exe",
        ),
        call(
            "SetEnvironmentVariableW",
            variable_name="PATH",
            variable_value=r"C:\Users\lab\Downloads",
        ),
        call(
            "CreateProcessW",
            application_name="",
            command_line="updater.exe",
            process_handle=2201,
        ),
        call(
            "QueryFullProcessImageNameW",
            process_handle=2201,
            flags=0,
            image_path=exe_path,
            character_count=len(exe_path),
        ),
    ],
    [
        [
            call("CreateFileW", path=exe_path, handle=64),
            call(
                "WriteFile",
                handle=64,
                bytes_transferred="@fixture_size",
                buffer_hex="@fixture:local_group_capability.exe",
            ),
            call(
                "SetEnvironmentVariableW",
                variable_name="PATH",
                variable_value=r"C:\Users\lab\Downloads",
            ),
            call(
                "CreateProcessW",
                application_name="",
                command_line="updater.exe",
                process_handle=2201,
            ),
            call(
                "QueryFullProcessImageNameW",
                process_handle=2201,
                flags=0,
                image_path=r"C:\Program Files\Lab\updater.exe",
                character_count=len(r"C:\Program Files\Lab\updater.exe"),
            ),
        ]
    ],
    "Requires actual child-image resolution to the planted executable after PATH modification and an unqualified launch request. Expected trusted helper, working-directory alternatives, causal search-order influence, and malicious intent still require qualification.",
    [close(), {"apis": ["closehandle"], "field": "handle", "binding": "child"}],
)


def get_cases(base_catalog):
    result = copy.deepcopy(CASES)
    dde = next(r for r in base_catalog["rules"] if r["attack_id"] == "T1559.002")
    result.append(
        dict(
            attack_id="T1559",
            name="execute a command through a bound DDE conversation",
            stages=dde["stages"],
            invalidate=dde["invalidate"],
            same_thread=True,
            positive_calls=[
                call("DdeConnect", handle=64),
                call(
                    "DdeClientTransaction",
                    conversation_handle=64,
                    transaction_type=16464,
                    timeout_ms=1000,
                    command="whoami",
                ),
            ],
            negative_calls=[
                [
                    call("DdeConnect", handle=64),
                    call(
                        "DdeClientTransaction",
                        conversation_handle=999,
                        transaction_type=16464,
                        timeout_ms=1000,
                        command="whoami",
                    ),
                ]
            ],
            note="A direct DDE command-execution predicate for the IPC parent technique. No automatic parent roll-up or malicious-intent claim.",
        )
    )
    return result
