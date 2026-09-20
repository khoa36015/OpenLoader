/**
 * PSEUDO — main.cpp
 * Entry point for the shellcode loader.
 * Parses CLI args, reads config.json, dispatches loader.
 */

#include "core/loader.h"
#include <cstdio>

int main(int argc, char* argv[]) {
    std::printf("=== OpenLoader v1.0.0 ===\n");

    // PSEUDO: parse CLI arguments
    // PSEUDO: read config.json → populate ModuleConfig
    core::ModuleConfig config{};
    config.bypass_static = true;
    config.bypass_etw = true;
    config.bypass_amsi = true;
    config.bypass_unhook = true;
    config.inject_process = true;

    core::Loader loader;
    if (loader.initialize(config) != core::Result::SUCCESS) {
        std::fprintf(stderr, "[!] Init failed\n");
        return 1;
    }

    // PSEUDO: if shellcode file provided, load it
    // if (argc >= 2) loader.load_from_file(argv[1]);

    loader.shutdown();
    return 0;
}
