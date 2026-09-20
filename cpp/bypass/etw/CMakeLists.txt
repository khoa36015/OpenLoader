# cpp/bypass/etw/CMakeLists.txt
# Layer 2: ETW telemetry blinding

add_library(bypass_etw STATIC
    src/etw_patcher.cpp
)
target_include_directories(bypass_etw PUBLIC include)
