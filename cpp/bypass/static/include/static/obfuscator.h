#ifndef STATIC_OBFUSCATOR_H
#define STATIC_OBFUSCATOR_H

/**
 * PSEUDO — obfuscator.h
 * Layer 1: Static analysis evasion.
 * Compile-time code obfuscation, opaque predicates, control flow flattening.
 */

#include <cstdint>
#include <cstddef>

namespace bypass {

class Obfuscator {
public:
    // Obfuscate a code region at runtime
    static void obfuscate(uint8_t* data, size_t size);

    // PSEUDO: add junk code / opaque predicates
    static void add_junk_code();

    // PSEUDO: flatten control flow
    static void flatten_flow();
};

} // namespace bypass

#endif // STATIC_OBFUSCATOR_H
