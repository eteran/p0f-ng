cmake_minimum_required(VERSION 3.0)

add_executable(p0f
    api_client.h
    p0f.cpp
)

target_compile_definitions(p0f
    PUBLIC
    -DVERSION=\"3.09b\"
    -DDEBUG_BUILD
)

target_compile_options(p0f
    PUBLIC
    -Wall
    -W
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
    -Wformat=2
    -Wformat-extra-args
    -Wformat-security
    -Wformat-y2k
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
    -Wnonnull
    -Wno-redundant-decls
    -Wno-undef
    -Wold-style-cast -pedantic
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
)

target_include_directories(p0f
    PUBLIC
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(p0f
    PUBLIC
    ${PCAP_LIBRARIES}
    p0f-engine
)

set_property(TARGET p0f PROPERTY CXX_EXTENSIONS OFF)
set_property(TARGET p0f PROPERTY CXX_STANDARD 17)
set_property(TARGET p0f PROPERTY RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
