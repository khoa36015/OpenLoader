# cpp/inject/CMakeLists.txt
# Injection techniques

add_library(openloader_inject STATIC
    src/process_inject.cpp
    src/module_stomp.cpp
)
target_include_directories(openloader_inject PUBLIC include)
