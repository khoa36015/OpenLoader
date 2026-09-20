# cpp/bypass/unhook/CMakeLists.txt
# Layer 4: NTDLL unhooking + direct/indirect syscalls

add_library(bypass_unhook STATIC
    src/unhooker.cpp
    src/syscalls.cpp
)
target_include_directories(bypass_unhook PUBLIC include)
