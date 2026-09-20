#ifndef INJECT_PROCESS_INJECT_H
#define INJECT_PROCESS_INJECT_H

/**
 * PSEUDO — process_inject.h
 * Classic process injection via CreateRemoteThread.
 */

#include <cstdint>
#include <cstddef>

namespace inject {

class ProcessInjector {
public:
    // Inject shellcode into target PID
    static bool inject(uint32_t pid, const uint8_t* shellcode, size_t size);

    // Inject by process name
    static bool inject_by_name(const char* name, const uint8_t* shellcode, size_t size);
};

} // namespace inject

#endif // INJECT_PROCESS_INJECT_H
