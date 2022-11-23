cmake_minimum_required(VERSION 3.0)

add_library(p0f-engine
    Reader.cpp
    Reader.h
    fp_http.cpp
    fp_mtu.cpp
    fp_tcp.cpp
    hash.h
    languages.h
    libp0f.cpp
    process.cpp
    readfp.cpp
    include/p0f/api.h
    include/p0f/config.h
    include/p0f/config_http.h
    include/p0f/debug.h
    include/p0f/fp_http.h
    include/p0f/fp_mtu.h
    include/p0f/fp_tcp.h
    include/p0f/ip_address.h
    include/p0f/libp0f.h
    include/p0f/memory.h
    include/p0f/process.h
    include/p0f/readfp.h
    include/p0f/tcp.h
    include/p0f/util.h
)

target_compile_definitions(p0f-engine
    PUBLIC
    -DVERSION=\"3.09b\"
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(p0f-engine
        PUBLIC
        -DDEBUG_BUILD
    )
endif()

target_include_directories(p0f-engine
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(p0f-engine
    PRIVATE
    -W
    -Wall
    -Wattributes
    -Wcast-align
    -Wchar-subscripts
    -Wcomment
    -Wdeprecated-declarations
    -Wdisabled-optimization
    -Wdiv-by-zero
    -Wendif-labels
    -Wextra
    -Wfloat-equal
    -Wformat-extra-args
    -Wformat-security
    -Wformat-y2k
    -Wformat=2
    -Winit-self
    -Wint-to-pointer-cast
    -Winvalid-pch
    -Wmain
    -Wmissing-braces
    -Wmissing-declarations
    -Wmissing-field-initializers
    -Wmissing-format-attribute
    -Wmissing-include-dirs
    -Wmultichar
    -Wno-error
    -Wno-missing-field-initializers
    -Wno-redundant-decls
    -Wno-undef
    -Wnonnull
    -Wold-style-cast
    -Woverflow
    -Wparentheses
    -Wpointer-arith
    -Wreturn-type
    -Wsequence-point
    -Wshadow
    -Wshadow
    -Wsign-compare
    -Wstrict-aliasing
    -Wswitch
    -Wtrigraphs
    -Wundef
    -Wunknown-pragmas
    -Wunused
    -Wunused-function
    -Wunused-label
    -Wunused-parameter
    -Wunused-value
    -Wunused-variable
    -Wuseless-cast
    -Wvariadic-macros
    -Wvla
    -Wvolatile-register-var
    -Wwrite-strings
    -pedantic
)

set_property(TARGET p0f-engine PROPERTY CXX_STANDARD 17)
set_property(TARGET p0f-engine PROPERTY CXX_EXTENSIONS OFF)
set_property(TARGET p0f-engine PROPERTY LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_property(TARGET p0f-engine PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
