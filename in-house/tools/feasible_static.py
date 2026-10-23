"""Static capability signatures; co-occurrence never proves runtime dataflow."""

SPECS = [
    (
        "T1546.016",
        "reference adding and scheduling an installer custom action",
        "function",
        [
            {"api": "MsiOpenDatabase"},
            {"api": "MsiDatabaseOpenView"},
            {"api": "MsiViewExecute"},
            {"api": "MsiDatabaseCommit"},
            {"string": "/\\AINSERT INTO `CustomAction` /i"},
            {"string": "/\\AINSERT INTO `InstallExecuteSequence` /i"},
        ],
        "References transactional MSI modification, custom-action insertion, install-sequence insertion, and database commit in one function. Actual record bindings, package identity, action payload, elevation, and install triggering remain unproven.",
    ),
    (
        "T1027.009",
        "contain a nested PE payload",
        "file",
        [{"format": "pe"}, {"characteristic": "embedded pe with valid sections"}],
        "A carved nested PE is an embedded-payload candidate; its maliciousness and execution are unproven.",
    ),
    (
        "T1027.001",
        "contain a large uniform PE overlay",
        "file",
        [{"format": "pe"}, {"characteristic": "large uniform pe overlay"}],
        "At least 64 KiB and one quarter of the file is uniform zero/FF overlay outside the certificate region. This is a structural padding candidate, not proof of deliberate scan evasion.",
    ),
    (
        "T1027.016",
        "contain a long run of executable no-operation instructions",
        "basic block",
        [
            {"or": [{"arch": "i386"}, {"arch": "amd64"}]},
            {"count(mnemonic(nop))": "32 or more"},
        ],
        "At least 32 decoded NOP instructions in a basic block are a junk-code candidate. Compiler alignment and benign code remain possible.",
    ),
    (
        "T1021.003",
        "reference remote MMC DCOM command activation",
        "function",
        [
            {"api": "CoCreateInstanceEx"},
            {"string": "MMC20.Application"},
            {"string": "ExecuteShellCommand"},
        ],
        "References the MMC automation command method alongside extended COM activation in one function. Remote server identity, method dispatch, and execution need qualification.",
    ),
    (
        "T1546.003",
        "reference the three WMI subscription object roles",
        "function",
        [
            {"api": "CoCreateInstance"},
            {"string": "__EventFilter"},
            {"string": "CommandLineEventConsumer"},
            {"string": "__FilterToConsumerBinding"},
        ],
        "References the filter, executable consumer, and binding roles in a COM-capable function. Successful persistence requires inspection of actual WMI objects and their bindings.",
    ),
    (
        "T1137.003",
        "reference Outlook form script configuration",
        "function",
        [
            {"api": "CoCreateInstance"},
            {"string": "Outlook.Application"},
            {"string": "FormDescription"},
            {"string": "ScriptText"},
        ],
        "References Outlook custom-form script configuration in a COM-capable function; form publication, startup triggers, and malicious content are unproven.",
    ),
    (
        "T1137.004",
        "reference Outlook folder web-view configuration",
        "function",
        [
            {"api": "CoCreateInstance"},
            {"string": "Outlook.Application"},
            {"string": "WebViewURL"},
            {"string": "WebViewOn"},
        ],
        "References both the URL and activation properties of an Outlook home page; actual property writes, page script, and startup execution need qualification.",
    ),
    (
        "T1137.005",
        "reference an Outlook rule application-start action",
        "function",
        [
            {"api": "CoCreateInstance"},
            {"string": "Outlook.Application"},
            {"string": "Rules"},
            {"string": "StartApplication"},
        ],
        "References Outlook rules and an application-start action in one COM-capable function; saved rule configuration and trigger execution remain unproven.",
    ),
    (
        "T1055.015",
        "reference remote list-view sorting callback injection",
        "function",
        [
            {"api": "OpenProcess"},
            {"api": "WriteProcessMemory"},
            {"api": "SendMessage"},
            {"number": 0x1030},
        ],
        "References remote memory writing and LVM_SORTITEMS (0x1030). A callback address, matching window/process identity, and control transfer still require qualification.",
    ),
    (
        "T1056.004",
        "reference patching a credential authentication API",
        "function",
        [
            {"api": "GetProcAddress"},
            {"string": "LsaLogonUser"},
            {"api": "VirtualProtect"},
            {"api": "WriteProcessMemory"},
        ],
        "References resolution of a credential API and memory patching in one function. Address/dataflow binding, hook installation, and credential interception remain unproven.",
    ),
    (
        "T1574.013",
        "reference a PEB callback-table modification workflow",
        "function",
        [
            {"api": "NtQueryInformationProcess"},
            {"api": "ReadProcessMemory"},
            {"api": "WriteProcessMemory"},
            {"api": "SendMessage"},
            {"number": 0x4A},
            {
                "or": [
                    {"and": [{"arch": "i386"}, {"offset": 0x2C}]},
                    {"and": [{"arch": "amd64"}, {"offset": 0x58}]},
                ]
            },
        ],
        "References the architecture-specific PEB KernelCallbackTable offset, remote memory operations, and WM_COPYDATA. Static co-occurrence cannot establish the actual pointer chain or callback execution.",
    ),
]
