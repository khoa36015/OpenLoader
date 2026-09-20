#ifndef UNHOOK_UNHOOKER_H
#define UNHOOK_UNHOOKER_H

/**
 * PSEUDO — unhooker.h
 * Layer 4a: NTDLL unhooking.
 * Restores hooked ntdll.dll .text section from clean copy.
 */

#include <cstdint>

namespace bypass {

class Unhooker {
public:
    // Restore ntdll .text from C:\Windows\System32\ntdll.dll
    static bool unhook_from_disk();

    // Restore from \KnownDlls\ntdll.dll (fileless)
    static bool unhook_from_known_dlls();

    // Verify unhooking succeeded (check first bytes)
    static bool verify();
};

} // namespace bypass

#endif // UNHOOK_UNHOOKER_H
