"""Explicit missing observables/backends, not declarations of impossibility."""

DEFERRED = {}


def require(ids, backend, reason):
    for attack_id in ids.split():
        assert attack_id not in DEFERRED
        DEFERRED[attack_id] = {
            "required_provider_or_backend": backend,
            "remaining_requirement": reason,
        }


require(
    "T1001.003",
    "protocol-conformance and impersonated-service context",
    "Distinguish deliberate imitation of another protocol/service's framing or identity from ordinary use of that protocol. Browser-UA configuration is separately modeled under T1036.012.",
)
require(
    "T1008",
    "failure-to-fallback branch/dataflow evidence",
    "Link a specific channel failure to the branch that selects a different working command channel; sequential unrelated connections are insufficient.",
)
require(
    "T1014",
    "kernel/object integrity and visibility baseline",
    "Bind a hiding/filtering/hook or DKOM modification to the actual hidden object and a trusted system view; loading a driver is insufficient.",
)
require(
    "T1027.008",
    "stripped-payload reconstruction/dataflow backend",
    "Identify the missing payload structures and the loader's reconstruction or mapping of those structures; a release binary's stripped symbols are insufficient.",
)
require(
    "T1027.014",
    "cross-variant semantic/code-generation analysis",
    "Establish generated variants with changing representations and equivalent payload behavior; one encrypted blob does not demonstrate polymorphism.",
)
require(
    "T1030",
    "source-segmentation and transfer-policy evidence",
    "Bind collected-source segments to separate transfers and a size-limiting policy, distinguishing that policy from normal packetization or buffered writes.",
)
require(
    "T1102.003",
    "explicit channel directionality or complete-session evidence",
    "Establish the configured one-way command/data role. An incomplete trace with no observed upload cannot establish the absence of reverse communication.",
)
require(
    "T1111",
    "MFA challenge/response and identity provenance",
    "Bind captured MFA material to the victim challenge and an unauthorized recipient/use; generic input or mail access is insufficient.",
)
require(
    "T1133",
    "remote-ingress boundary and authenticated-session evidence",
    "Establish outside-origin access to the exposed service and the resulting session. A remote hostname, VPN utility, or outbound tunnel alone cannot establish external ingress.",
)
require(
    "T1185",
    "authenticated browser-session and action provenance",
    "Bind manipulation to the victim's already authenticated browser session and resulting actions; a debugging port alone is insufficient.",
)
require(
    "T1189 T1190 T1203 T1210 T1211 T1499.004 T1611 T1687",
    "vulnerability and violated-boundary validation",
    "Identify the vulnerable target/version, delivered input, flaw-triggered transition, and technique-specific access, impact, or boundary crossing. A crash, exploit-tool name, or CVE string is insufficient.",
)
require(
    "T1195 T1195.001 T1195.002 T1195.003",
    "build/distribution or hardware supply-chain provenance",
    "Establish the trusted upstream artifact/component, unauthorized upstream modification, and downstream delivery/use. A standalone payload cannot recover that historical provenance.",
)
require(
    "T1199",
    "cross-organization trust and access records",
    "Establish the compromised partner identity and the actual victim access obtained through its trusted relationship.",
)
require(
    "T1200 T1219.003 T1669",
    "device/radio topology and physical-access records",
    "Identify the introduced or remote-access hardware/radio, its actual connection and access role, and victim topology; ordinary device enumeration is insufficient.",
)
require(
    "T1204 T1204.001 T1204.002 T1204.004 T1204.005",
    "human-interaction and delivered-artifact provenance",
    "Link the actual user action to the delivered link/file/library or pasted command and subsequent execution. CreateProcess does not identify a human trigger.",
)
require(
    "T1205 T1205.001",
    "network-trigger state machine and gated-service evidence",
    "Link the received signaling/knock sequence to the state transition enabling access or commands; a sequence of connection attempts is insufficient.",
)
require(
    "T1480 T1480.001 T1480.002 T1497.003 T1679",
    "input/branch/payload causal analysis",
    "Recover the actual condition/key/mutual-exclusion/timing or exclusion comparison and its effect on payload execution, decryption, or skipped targets. API co-occurrence does not establish that dependency.",
)
require(
    "T1491 T1491.001 T1491.002",
    "rendered-content baseline and audience scope",
    "Bind unauthorized replacement to the actual presented site/interface and its internal/external audience. Routine web-root writes do not establish defacement.",
)
require(
    "T1495 T1542.002",
    "device-bound firmware image/flash validation",
    "Bind the operation to a specific component firmware region and persisted modified/corrupted image. BIOS queries or UEFI configuration changes are insufficient.",
)
require(
    "T1496.002",
    "bandwidth-sharing workload and account/authorization context",
    "Establish the actual bandwidth contribution/proxyware workload, its beneficiary, and unauthorized use; generic proxying is insufficient.",
)
require(
    "T1498.002",
    "forged-source and reflector amplification evidence",
    "Bind a reflection-capable request to its forged victim source and amplification/reflector role; generic UDP traffic or a high send rate is insufficient.",
)
require(
    "T1499.002 T1499.003",
    "target service/application resource telemetry",
    "Bind the protocol/application-specific workload to resource exhaustion at the actual target. Many requests or connection attempts alone do not establish the relevant exhaustion mechanism.",
)
require(
    "T1534 T1566 T1566.001 T1566.002 T1566.003 T1566.004",
    "delivery-message, channel, and identity provenance",
    "Inspect the actual lure, payload/link/voice or service delivery and sender/victim relationship; internal spearphishing additionally needs organizational and compromised-account context. Later payload execution cannot reconstruct these facts.",
)
require(
    "T1557 T1557.001 T1557.002 T1557.003",
    "packet relay/poisoning plus network-ownership baseline",
    "Bind on-path relay or forged name/ARP/DHCP information to the legitimate ownership/topology and affected victim session. Ordinary resolution, address announcements, or a proxy API is insufficient.",
)
require(
    "T1564.007",
    "version-aware Office source/p-code comparison backend",
    "Parse VBA source and compiled p-code and establish a meaningful discrepancy with supported Office versions; the mere presence of macros or p-code is insufficient.",
)
require(
    "T1565.003",
    "domain-specific runtime-data and outcome provenance",
    "Identify the application data object and the altered decision/output resulting from its manipulation. Generic remote memory writes or code injection are insufficient.",
)
require(
    "T1568.002",
    "generated-name input/algorithm dataflow",
    "Link the name-generation algorithm and seed/input to actual queried C2 names; entropy or NXDOMAIN counts alone are insufficient.",
)
require(
    "T1568.003",
    "DNS-result-to-endpoint arithmetic dataflow",
    "Recover the actual transformation of a DNS result into the used endpoint; different or adjacent address values alone do not establish a calculation.",
)
require(
    "T1574.005 T1574.009 T1574.010 T1574.011",
    "effective ACL/search-resolution and privileged-consumer evidence",
    "Bind the writable installer/service file or registry configuration, or ambiguous unquoted command, to the actual substituted object selected by the privileged consumer. Setting permissions or finding an unquoted path alone is insufficient.",
)
require(
    "T1606 T1606.001 T1606.002",
    "credential issuer authority, signing, and relying-party validation",
    "Distinguish unauthorized forged cookies/SAML credentials from legitimate issuance using the issuer/key/claims baseline and actual relying-party use. Signing or encoding arbitrary data is insufficient.",
)
require(
    "T1621",
    "MFA request/approval and user/account records",
    "Bind repeated unsolicited MFA prompts to the target identity and actual authentication workflow; ordinary network repetition is insufficient.",
)
require(
    "T1657",
    "financial transaction and authorization records",
    "Establish the unauthorized transfer or financial outcome and affected account/business context; banking strings or network access are insufficient.",
)
require(
    "T1659",
    "in-transit content replacement and delivery provenance",
    "Establish the original and replaced content, injection point, and victim delivery across the trusted channel; writing or downloading content is insufficient.",
)
require(
    "T1665",
    "infrastructure ownership and concealment relationships",
    "Establish the adversary-controlled infrastructure and its actual concealment relationship; endpoint strings or ordinary proxy use are insufficient.",
)
require(
    "T1667",
    "mail delivery volume and recipient impact",
    "Establish delivered unsolicited message volume and the targeted mailbox's disruption; SMTP capability or repeated sends alone are insufficient.",
)
require(
    "T1668",
    "competing-actor foothold and exclusion intent/context",
    "Link cleanup/patching/permission changes to preventing competing actors' access after compromise. Ordinary remediation cannot establish exclusive adversary control.",
)
require(
    "T1684 T1684.001 T1684.002",
    "human communication, asserted identity, and trusted-origin records",
    "Establish the deceptive interaction and identity/origin discrepancy, including authenticated email provenance for spoofing; a UI label or From header alone is insufficient.",
)
require(
    "T1685.003",
    "security-tool UI versus independently measured protection state",
    "Bind misleading health/status presentation to the actual impaired tool state and affected interface. Drawing a security-looking window alone is insufficient.",
)
