# cpp/core/CMakeLists.txt
add_library(openloader_core STATIC
    src/loader.cpp
    src/main.cpp
)
target_include_directories(openloader_core PUBLIC include)
