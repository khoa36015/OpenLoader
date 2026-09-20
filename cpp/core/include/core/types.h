#ifndef CORE_TYPES_H
#define CORE_TYPES_H

/**
 * PSEUDO — types.h
 * Common type definitions for the shellcode loader.
 */

#include <cstdint>
#include <cstddef>

namespace core {

// Module enable flags (populated from config.json at build time)
struct ModuleConfig {
    bool bypass_static;
    bool bypass_etw;
    bool bypass_amsi;
    bool bypass_unhook;
    bool inject_process;
    bool inject_stomp;
};

// Execution result
enum class Result : uint32_t {
    SUCCESS = 0,
    FAILED,
    MODULE_DISABLED,
    // TODO: add more
};

} // namespace core

#endif // CORE_TYPES_H
