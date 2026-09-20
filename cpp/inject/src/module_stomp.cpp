/**
 * PSEUDO — module_stomp.cpp
 * Module stomping implementation.
 * Loadlegitimate DLL → overwrite its .text → no new thread needed.
 */

#include "inject/module_stomp.h"

namespace inject {

bool ModuleStomp::stomp(uint32_t pid, const char* dll_name,
                         const uint8_t* shellcode, size_t size) {
    // PSEUDO:
    // 1. Open target process
    // 2. Create remote thread calling LoadLibraryA(dll_name)
    // 3. Wait for thread to finish (DLL loaded in target)
    // 4. Find DLL base address in target
    // 5. Find .text section
    // 6. VirtualProtect → RWX
    // 7. WriteProcessMemory with shellcode
    // 8. VirtualProtect → RX
    // 9. FlushInstructionCache
    (void)pid; (void)dll_name; (void)shellcode; (void)size;
    return true;
}

} // namespace inject
