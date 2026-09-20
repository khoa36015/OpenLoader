# cpp/bypass/static/CMakeLists.txt
# Layer 1: Static AV/EDR evasion (string encryption, IAT camouflage)

add_library(bypass_static STATIC
    src/obfuscator.cpp
    src/string_encrypt.cpp
)
target_include_directories(bypass_static PUBLIC include)
