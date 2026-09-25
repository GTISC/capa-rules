/* Benign static-analysis fixture: this program is not run by the smoke test. */
#include <windows.h>
#include <lm.h>

__declspec(noinline) static DWORD inspect_local_groups(void) {
    LPBYTE groups = NULL;
    LPBYTE members = NULL;
    DWORD groups_read = 0, groups_total = 0, members_read = 0, members_total = 0;
    DWORD group_resume = 0, member_resume = 0;
    NET_API_STATUS first = NetLocalGroupEnum(NULL, 0, &groups, MAX_PREFERRED_LENGTH,
                                               &groups_read, &groups_total, &group_resume);
    NET_API_STATUS second = NetLocalGroupGetMembers(NULL, L"Administrators", 0,
                                                      &members, MAX_PREFERRED_LENGTH,
                                                      &members_read, &members_total,
                                                      &member_resume);
    if (groups) NetApiBufferFree(groups);
    if (members) NetApiBufferFree(members);
    return first + second;
}

int main(void) { return (int)inspect_local_groups(); }
