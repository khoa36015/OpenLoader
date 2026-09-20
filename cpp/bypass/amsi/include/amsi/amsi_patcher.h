#ifndef AMSI_AMSI_PATCHER_H
#define AMSI_AMSI_PATCHER_H

/**
 * PSEUDO — amsi_patcher.h
 * Layer 3: AMSI (Antimalware Scan Interface) bypass.
 * Patches AmsiScanBuffer to return clean result.
 */

#include <cstdint>

namespace bypass {

class AMSIPatcher {
public:
    // Patch AmsiScanBuffer with 'ret' (bypass scan)
    static bool patch_ret();

    // Patch with 'xor eax,eax; ret' (return AMSI_RESULT_CLEAN)
    static bool patch_clean();

    // Null the AmsiContext pointer
    static bool patch_context();

    // Restore original bytes
    static void restore();
};

} // namespace bypass

#endif // AMSI_AMSI_PATCHER_H
