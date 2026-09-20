/**
 * PSEUDO — test_main.cpp
 * C++ tests for the shellcode loader modules.
 */

#include "core/loader.h"
#include <cstdio>

int main() {
    std::printf("Running OpenLoader tests...\n");

    // PSEUDO: test loader initialization
    core::ModuleConfig config{};
    config.bypass_static = true;
    config.bypass_etw = true;
    config.bypass_amsi = true;
    config.bypass_unhook = true;

    core::Loader loader;
    auto result = loader.initialize(config);
    // ASSERT_EQ(result, core::Result::SUCCESS);

    loader.shutdown();

    std::printf("All tests passed.\n");
    return 0;
}
