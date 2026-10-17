/* Harmless DLL used only as parsed data in detector regression cases. */
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
