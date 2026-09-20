#ifndef ETW_ETW_PATCHER_H
#define ETW_ETW_PATCHER_H

/**
 * PSEUDO — etw_patcher.h
 * Layer 2: ETW (Event Tracing for Windows) bypass.
 * Patches EtwEventWrite / NtTraceEvent to silence telemetry.
 */

#include <cstdint>

namespace bypass {

class ETWPatcher {
public:
    // Patch EtwEventWrite to return immediately (ret / xor eax,eax; ret)
    static bool patch_event_write();

    // Patch NtTraceEvent to disable kernel ETW-TI
    static bool patch_nt_trace_event();

    // Restore original bytes (cleanup)
    static void restore();
};

} // namespace bypass

#endif // ETW_ETW_PATCHER_H
