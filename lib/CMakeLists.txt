cmake_minimum_required(VERSION 3.0)

find_package(Boost 1.61 REQUIRED)

add_library(p0f-engine
    fp_http.cpp
    fp_mtu.cpp
    fp_tcp.cpp
    include/p0f/api.h
    include/p0f/config.h
    include/p0f/debug.h
    include/p0f/ext/optional.h
    include/p0f/ext/string_view.h
    include/p0f/fp_http.h
    include/p0f/fp_mtu.h
    include/p0f/fp_tcp.h
	hash.h
	languages.h
	include/p0f/libp0f.h
	Reader.h
    include/p0f/process.h
    include/p0f/readfp.h
    include/p0f/tcp.h
	include/p0f/memory.h
    include/p0f/util.h
	include/p0f/ip_address.h
	include/p0f/config_http.h
    Reader.cpp
    process.cpp
    readfp.cpp
	libp0f.cpp
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
endif ()


target_include_directories(p0f-engine 
PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(p0f-engine
PUBLIC
	Boost::boost
)

target_compile_options(p0f-engine
PRIVATE
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

set_property(TARGET p0f-engine PROPERTY CXX_STANDARD 14)
set_property(TARGET p0f-engine PROPERTY CXX_EXTENSIONS OFF)
set_property(TARGET p0f-engine PROPERTY LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_property(TARGET p0f-engine PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
