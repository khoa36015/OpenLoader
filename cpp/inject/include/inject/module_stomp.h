#ifndef INJECT_MODULE_STOMP_H
#define INJECT_MODULE_STOMP_H

/**
 * PSEUDO — module_stomp.h
 * Module stomping — overwrite a legitimate DLL's .text section.
 */

#include <cstdint>
#include <cstddef>

namespace inject {

class ModuleStomp {
public:
    // Load a DLL into target, then overwrite its .text with shellcode
    static bool stomp(uint32_t pid, const char* dll_name,
                      const uint8_t* shellcode, size_t size);
};

} // namespace inject

#endif // INJECT_MODULE_STOMP_H
