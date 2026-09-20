# cpp/bypass/amsi/CMakeLists.txt
# Layer 3: AMSI scan bypass

add_library(bypass_amsi STATIC
    src/amsi_patcher.cpp
)
target_include_directories(bypass_amsi PUBLIC include)
