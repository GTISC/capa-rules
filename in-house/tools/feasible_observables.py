"""Reviewed concrete file and registry variants; no API-only technique tags."""

FILES = []
REGISTRY = []


def file(attack_id, action, pattern, positive, negative, note, **extra):
    FILES.append(
        dict(
            attack_id=attack_id,
            action=action,
            pattern="(?i)" + pattern,
            positive=positive,
            negative=negative,
            note=note,
            **extra,
        )
    )


def registry(
    attack_id,
    key,
    value,
    data,
    positive_key,
    positive_value,
    positive_data,
    negative_data,
    note,
    action="set",
):
    REGISTRY.append(
        dict(
            attack_id=attack_id,
            action=action,
            key_pattern="(?i)" + key,
            value_pattern="(?i)" + value,
            data=data,
            positive_key=positive_key,
            positive_value=positive_value,
            positive_data=positive_data,
            negative_data=negative_data,
            note=note,
        )
    )


file(
    "T1005",
    "read",
    r"\A[A-Z]:\\Users\\[^\\]+\\(?:Documents|Desktop)\\[^\r\n]+\.(?:docx?|xlsx?|pdf|txt|csv)\Z",
    r"C:\Users\lab\Documents\report.docx",
    r"C:\Windows\System32\kernel32.dll",
    "Reads nonempty content from a bound user-document handle; collection intent is unproven.",
)
file(
    "T1037",
    "write",
    r"\A[A-Z]:\\Windows\\System32\\GroupPolicy\\(?:User|Machine)\\Scripts\\(?:Logon|Startup)\\[^\\]+\.(?:bat|cmd|ps1|vbs)\Z",
    r"C:\Windows\System32\GroupPolicy\User\Scripts\Logon\lab.bat",
    r"C:\temp\lab.bat",
    "Writes a script in a concrete Group Policy boot/logon script directory; policy registration and invocation need qualification.",
)
file(
    "T1037.003",
    "write",
    r"\A\\\\[^\\]+\\SYSVOL\\[^\\]+\\scripts\\[^\r\n]+\.(?:bat|cmd|ps1|vbs)\Z",
    r"\\dc\SYSVOL\lab.local\scripts\logon.bat",
    r"C:\temp\logon.bat",
    "Writes a network-domain logon script location; active policy assignment is unproven.",
)
file(
    "T1114.001",
    "read",
    r"\A[A-Z]:\\Users\\[^\\]+\\(?:AppData\\Local\\Microsoft\\Outlook|Documents\\Outlook Files)\\[^\\]+\.(?:pst|ost)\Z",
    r"C:\Users\lab\AppData\Local\Microsoft\Outlook\mail.ost",
    r"C:\Users\lab\Documents\report.docx",
    "Reads nonempty content from a bound Outlook mail-store file.",
)
file(
    "T1137",
    "write",
    r"\A[A-Z]:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Templates\\Normal\.dotm\Z",
    r"C:\Users\lab\AppData\Roaming\Microsoft\Templates\Normal.dotm",
    r"C:\Users\lab\Documents\normal.docx",
    "Writes Word's startup template, a concrete Office startup mechanism; malicious macros and invocation are unproven.",
)
file(
    "T1137.001",
    "write",
    r"\A[A-Z]:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\(?:Templates\\Normal\.dotm|Excel\\XLSTART\\PERSONAL\.XLSB)\Z",
    r"C:\Users\lab\AppData\Roaming\Microsoft\Templates\Normal.dotm",
    r"C:\Users\lab\Documents\normal.docx",
    "Writes a documented Office startup macro template; macro content and execution need qualification.",
)
file(
    "T1217",
    "read",
    r"\A[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\(?:Google\\Chrome|Microsoft\\Edge)\\User Data\\(?:Default|Profile [0-9]+)\\(?:History|Bookmarks|Preferences)\Z",
    r"C:\Users\lab\AppData\Local\Google\Chrome\User Data\Default\History",
    r"C:\Users\lab\Documents\History.txt",
    "Reads nonempty browser history/bookmark/preference data from a bound profile file.",
)
file(
    "T1546.018",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\\(?:site-packages\\)?(?:sitecustomize|usercustomize)\.py\Z",
    r"C:\Python311\Lib\site-packages\sitecustomize.py",
    r"C:\temp\normal.py",
    "Writes a Python startup-hook module; interpreter search-path membership and execution remain unproven.",
)
file(
    "T1552",
    "read",
    r"\A[A-Z]:\\Users\\[^\\]+\\\.aws\\credentials\Z",
    r"C:\Users\lab\.aws\credentials",
    r"C:\Users\lab\Documents\credentials.txt",
    "Reads a concrete unsecured credential store, a direct parent-technique implementation.",
)
file(
    "T1552.003",
    "read",
    r"\A[A-Z]:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history\.txt\Z",
    r"C:\Users\lab\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    r"C:\Users\lab\Documents\history.txt",
    "Reads a persistent PowerShell history file that may contain credentials.",
)
file(
    "T1552.006",
    "read",
    r"\A\\\\[^\\]+\\SYSVOL\\[^\\]+\\Policies\\\{[0-9a-f-]{36}\}\\(?:Machine|User)\\Preferences\\(?:Groups\\Groups|Services\\Services|ScheduledTasks\\ScheduledTasks|Drives\\Drives)\.xml\Z",
    r"\\dc\SYSVOL\lab.local\Policies\{00000000-0000-0000-0000-000000000001}\Machine\Preferences\Groups\Groups.xml",
    r"\\dc\share\Groups.xml",
    "Reads a bound domain Group Policy Preferences credential-bearing artifact; an actual cpassword and decryption are unproven.",
)
file(
    "T1036",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.(?:pdf|docx?|xlsx?|jpg|png)\.(?:exe|scr)\Z",
    r"C:\stage\report.pdf.exe",
    r"C:\stage\report.exe",
    "Writes a filename disguising an executable extension behind a document extension; file content and user presentation remain unproven.",
)
file(
    "T1036.002",
    "write",
    "\\A[A-Z]:\\\\[^\\r\\n]*\u202e[^\\\\\\r\\n]+\\.(?:exe|scr)\\Z",
    "C:\\stage\\report\u202efdp.exe",
    r"C:\stage\report.exe",
    "Writes a concrete filename containing the right-to-left override control character.",
)
file(
    "T1036.007",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.(?:pdf|docx?|xlsx?|jpg|png)\.(?:exe|scr)\Z",
    r"C:\stage\report.pdf.exe",
    r"C:\stage\report.exe",
    "Writes a document-like double-extension executable filename; the content and displayed disguise require qualification.",
)
file(
    "T1539",
    "read",
    r"\A[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\(?:Google\\Chrome|Microsoft\\Edge)\\User Data\\(?:Default|Profile [0-9]+)\\(?:Network\\)?Cookies\Z",
    r"C:\Users\lab\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
    r"C:\Users\lab\Documents\cookies.txt",
    "Reads a bound browser cookie store; actual session-token contents, extraction, and reuse remain unproven.",
)
file(
    "T1547.008",
    "write",
    r"\A[A-Z]:\\Windows\\System32\\(?:msv1_0|lsasrv|samsrv)\.dll\Z",
    r"C:\Windows\System32\msv1_0.dll",
    r"C:\stage\normal.dll",
    "Writes an LSASS security-subsystem DLL path; existing identity, actual replacement, load, and persistence need qualification.",
)
file(
    "T1036.008",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.(?:pdf|docx?|xlsx?|jpe?g|png)\Z",
    r"C:\stage\invoice.pdf",
    r"C:\stage\program.exe",
    "Writes a structurally parsed PE under a document/image extension; an MZ string alone is insufficient.",
    payload_op="pe_hex",
    positive_fixture="local_group_capability.exe",
)
file(
    "T1036.005",
    "write",
    r"\A[A-Z]:\\Users\\[^\\]+\\(?:AppData\\Local\\Temp|Downloads)\\(?:lsass|svchost|winlogon)\.exe\Z",
    r"C:\Users\lab\Downloads\svchost.exe",
    r"C:\Windows\System32\svchost.exe",
    "Writes a parsed PE with a core Windows process name outside its standard system location; publisher identity and deception intent are unproven.",
    payload_op="pe_hex",
    positive_fixture="local_group_capability.exe",
)
file(
    "T1027.006",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.html?\Z",
    r"C:\stage\delivery.html",
    r"C:\stage\delivery.txt",
    "Writes HTML that constructs a Blob, creates its object URL, and assigns a download filename; payload identity and filter evasion remain unproven.",
    payload_pattern=r"(?s)\A(?=.{0,8192}new\s+Blob\s*\()(?=.{0,8192}URL\.createObjectURL\s*\()(?=.{0,8192}\.download\s*=)",
    positive_text='<html><script>const blob = new Blob([bytes]); const u = URL.createObjectURL(blob); a.download = "payload.bin";</script></html>',
    negative_text="<html><p>A normal download page</p></html>",
)
file(
    "T1027.017",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.svg\Z",
    r"C:\stage\image.svg",
    r"C:\stage\image.txt",
    "Writes SVG containing a script that constructs a downloadable Blob; static image markup alone is insufficient.",
    payload_pattern=r"(?s)\A(?=.{0,8192}<svg\b)(?=.{0,8192}<script\b)(?=.{0,8192}new\s+Blob\s*\()(?=.{0,8192}URL\.createObjectURL\s*\()",
    positive_text='<svg xmlns="http://www.w3.org/2000/svg"><script>const b = new Blob([bytes]); a.href = URL.createObjectURL(b);</script></svg>',
    negative_text='<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>',
)
file(
    "T1027.018",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.(?:js|html?)\Z",
    r"C:\stage\script.js",
    r"C:\stage\script.txt",
    "Writes a script with an invisible-character data sequence and dynamic evaluation; decoding/dataflow and malicious purpose still need qualification.",
    payload_pattern="(?s)\\A(?=.{0,8192}[\u200b\u200c\u200d\u2060\ufe00-\ufe0f]{16})(?=.{0,8192}\\beval\\s*\\()",
    positive_text='const hidden="' + "\u200b\u200c" * 16 + '"; eval(decode(hidden));',
    negative_text='const visible="ordinary text"; console.log(visible);',
)
file(
    "T1505.003",
    "write",
    r"\A[A-Z]:\\inetpub\\wwwroot\\[^\r\n]+\.php\Z",
    r"C:\inetpub\wwwroot\lab.php",
    r"C:\stage\lab.php",
    "Writes PHP in a web-root location that passes a request parameter directly to an OS command sink; actual server configuration and remote execution remain unproven.",
    payload_pattern=r'(?s)<\?php\s+(?:system|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\x27"]\w+[\x27"]\s*\]\s*\)',
    positive_text="<?php system($_GET['cmd']); ?>",
    negative_text="<?php echo 'Welcome'; ?>",
)
file(
    "T1565",
    "write",
    r"\A[A-Z]:\\Windows\\System32\\drivers\\etc\\hosts\Z",
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\stage\hosts",
    "Writes concrete hostname-to-address mappings into the system hosts file; adversary intent and deviation from an authorized baseline remain unproven.",
    payload_pattern=r"(?m)^[ \t]*(?:[0-9]{1,3}\.){3}[0-9]{1,3}[ \t]+[A-Za-z0-9][A-Za-z0-9.-]+(?:[ \t]*\r?$)",
    positive_text="192.0.2.1 portal.lab.local\n",
    negative_text="# ordinary hosts comment\n",
)
file(
    "T1565.001",
    "write",
    r"\A[A-Z]:\\Windows\\System32\\drivers\\etc\\hosts\Z",
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\stage\hosts",
    "Writes hostname-resolution data into a bound hosts file, a concrete stored-data manipulation mechanism; authorization and malicious redirection need qualification.",
    payload_pattern=r"(?m)^[ \t]*(?:[0-9]{1,3}\.){3}[0-9]{1,3}[ \t]+[A-Za-z0-9][A-Za-z0-9.-]+(?:[ \t]*\r?$)",
    positive_text="192.0.2.1 portal.lab.local\n",
    negative_text="# ordinary hosts comment\n",
)
file(
    "T1056.003",
    "write",
    r"\A[A-Z]:\\inetpub\\wwwroot\\[^\r\n]*login\.php\Z",
    r"C:\inetpub\wwwroot\login.php",
    r"C:\stage\login.php",
    "Writes a web-portal script that places submitted password data in an append-only capture file; legitimate portal baseline and actual credential interception remain unproven.",
    payload_pattern=r"""(?is)\A.{0,8192}<\?php\s+file_put_contents\s*\(\s*["'][^"']+["']\s*,\s*\$_POST\s*\[\s*["']password["']\s*\]\s*,\s*FILE_APPEND\s*\)""",
    positive_text="<?php file_put_contents('captured.txt', $_POST['password'], FILE_APPEND); ?>",
    negative_text="<?php echo 'Login'; ?>",
)
file(
    "T1187",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.url\Z",
    r"C:\stage\document.url",
    r"C:\stage\document.txt",
    "Writes an Internet Shortcut with a UNC icon resource that can initiate SMB authentication when rendered; actual rendering, authentication, and adversary control of the peer require qualification.",
    payload_pattern=r"(?ims)\A(?=.{0,8192}^\[InternetShortcut\]\r?$)(?=.{0,8192}^IconFile=\\\\[^\\\r\n]+\\[^\r\n]+)",
    positive_text="[InternetShortcut]\r\nURL=https://example.invalid/\r\nIconFile=\\\\fileserver\\icons\\icon.ico\r\n",
    negative_text="[InternetShortcut]\r\nURL=https://example.invalid/\r\nIconFile=C:\\icons\\icon.ico\r\n",
)
file(
    "T1080",
    "write",
    r"\A\\\\[^\\]+\\[^\\]+\\[^\r\n]+\.vbs\Z",
    r"\\fileserver\shared\startup.vbs",
    r"C:\stage\startup.vbs",
    "Writes an executable command-launching script onto a shared location. Previously trusted content, victim invocation, and unauthorized tainting require qualification.",
    payload_pattern=r"""(?is)\A(?=.{0,8192}CreateObject\s*\(\s*["']WScript\.Shell["']\s*\))(?=.{0,8192}\.Run\s+["'][^"']+["'])""",
    positive_text='Set s = CreateObject("WScript.Shell")\r\ns.Run "cmd.exe /c whoami"',
    negative_text='WScript.Echo "Welcome"',
)
file(
    "T1027.012",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.lnk\Z",
    r"C:\stage\shortcut.lnk",
    r"C:\stage\shortcut.txt",
    "Parses a complete LNK with a remote payload URL in its icon metadata and matching utility execution arguments. An arbitrary URL or icon string cannot satisfy this predicate; actual shell retrieval remains unproven.",
    payload_op="lnk_icon_hex",
    positive_fixture="feasible_icon.lnk",
)
file(
    "T1221",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.(?:docx|docm)\Z",
    r"C:\stage\document.docx",
    r"C:\stage\document.txt",
    "Parses an OOXML attached-template relationship with External mode and an HTTP macro-template target. Actual Office loading, macro execution, and malicious content remain unproven.",
    payload_op="remote_template_hex",
    positive_fixture="feasible_template.docx",
)
file(
    "T1027.003",
    "write",
    r"\A[A-Z]:\\[^\r\n]+\.bmp\Z",
    r"C:\stage\image.bmp",
    r"C:\stage\image.txt",
    "Parses an executable hidden in the pixel LSBs of a 24-bit BMP using one explicit length-prefixed variant. Random image entropy or arbitrary embedded strings do not qualify; intent and runtime extraction remain unproven.",
    payload_op="bmp_hidden_pe_hex",
    positive_fixture="feasible_hidden.bmp",
)
file(
    "T1556.007",
    "write",
    r"\A[A-Z]:\\Windows\\ADFS\\Microsoft\.IdentityServer\.Servicehost\.exe\.config\Z",
    r"C:\Windows\ADFS\Microsoft.IdentityServer.Servicehost.exe.config",
    r"C:\stage\service.config",
    "Writes an AD FS service configuration with actual runtime AppDomainManager assembly/type elements. A commented string cannot satisfy the XML parser. Existing service identity, malicious DLL behavior, load, and authentication bypass require qualification.",
    payload_op="appdomain_config_hex",
    positive_fixture="feasible_adfs.config",
)

BASE = r"\A(?:HKLM|HKEY_LOCAL_MACHINE)\\"
USER = r"\A(?:HKCU|HKEY_CURRENT_USER)\\"
ANY = r"(?s)\A.+\Z"
DLL = r"(?i)\A[A-Z]:\\[^\r\n]+\.dll\Z"

registry(
    "T1137.002",
    (BASE + r"SOFTWARE\\Microsoft\\Office test\\Special\Z"),
    r"\APerf\Z",
    DLL,
    r"HKLM\SOFTWARE\Microsoft\Office test\Special",
    "Perf",
    r"C:\stage\test.dll",
    r"C:\stage\test.txt",
    "Sets the Office Test Perf DLL value on its exact key, not an arbitrary Office setting.",
)
registry(
    "T1176.001",
    BASE
    + r"SOFTWARE\\Policies\\(?:Google\\Chrome|Microsoft\\Edge)\\ExtensionInstallForcelist\Z",
    r"\A[1-9][0-9]*\Z",
    r"\A[a-p]{32};https://[^\s]+\Z",
    r"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    "1",
    "abcdefghijklmnopabcdefghijklmnop;https://example.invalid/update.xml",
    "not-an-extension",
    "Adds a force-installed browser extension policy with an extension ID and update URL; extension code and load require qualification.",
)
registry(
    "T1505.005",
    BASE + r"SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters\Z",
    r"\AServiceDll\Z",
    DLL,
    r"HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters",
    "ServiceDll",
    r"C:\stage\service.dll",
    r"C:\stage\service.txt",
    "Redirects the Terminal Services DLL configuration; later service loading and binary provenance remain unproven.",
)
registry(
    "T1546.007",
    BASE + r"SOFTWARE\\Microsoft\\Netsh\Z",
    r"\A[^\\\r\n]+\Z",
    DLL,
    r"HKLM\SOFTWARE\Microsoft\Netsh",
    "LabHelper",
    r"C:\stage\helper.dll",
    r"C:\stage\helper.txt",
    "Registers a DLL on the exact Netsh helper key, without inferring later execution.",
)
registry(
    "T1553.003",
    BASE
    + r"SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Cryptography\\OID\\EncodingType 0\\(?:CryptSIPDllGetSignedDataMsg|CryptSIPDllVerifyIndirectData)\\\{[0-9a-f-]{36}\}\Z",
    r"\ADll\Z",
    DLL,
    r"HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{00000000-0000-0000-0000-000000000001}",
    "Dll",
    r"C:\stage\provider.dll",
    "unchanged",
    "Redirects a concrete signature-verification SIP DLL; its return behavior and trust bypass need qualification.",
)
registry(
    "T1564.002",
    BASE
    + r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\Z",
    r"\A[^\\\r\n]+\Z",
    0,
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
    "labuser",
    0,
    1,
    "Sets a named user logon-screen visibility DWORD to zero.",
)
registry(
    "T1574.014",
    USER + r"Environment\Z",
    r"\AAPPDOMAIN_MANAGER_ASM\Z",
    r"\A[A-Za-z_][\w., =-]+\Z",
    r"HKCU\Environment",
    "APPDOMAIN_MANAGER_ASM",
    "LabManager, Version=1.0.0.0",
    "",
    "Sets an AppDomainManager assembly-selection environment variable; the paired type, target .NET process, and assembly load remain unproven.",
)
registry(
    "T1552.002",
    USER + r"Software\\SimonTatham\\PuTTY\\Sessions\\[^\\]+\Z",
    r"\APassword\Z",
    ANY,
    r"HKCU\Software\SimonTatham\PuTTY\Sessions\Lab",
    "Password",
    "example-only",
    "",
    "Reads an explicit password value from a PuTTY session key; credential use is not inferred.",
    action="query",
)
registry(
    "T1518.002",
    BASE + r"SOFTWARE\\Veeam\\[^\r\n]+\Z",
    r"\A(?:InstallPath|Version)\Z",
    ANY,
    r"HKLM\SOFTWARE\Veeam\Veeam Backup and Replication",
    "InstallPath",
    r"C:\Program Files\Veeam",
    "",
    "Queries installation/version information on an exact backup software configuration key.",
    action="query",
)
