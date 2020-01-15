cmake_minimum_required(VERSION 3.0)

add_library(p0f-engine
    fp_http.cpp
    fp_tcp.cpp
    fp_mtu.cpp
    process.cpp
    include/p0f/api_client.h
    include/p0f/tcp.h
    include/p0f/p0f.h
    include/p0f/config.h
    include/p0f/debug.h
    include/p0f/alloc-inl.h
    include/p0f/types.h
    include/p0f/process.h
    include/p0f/fp_http.h
    include/p0f/fp_tcp.h
    include/p0f/languages.h
    include/p0f/readfp.h
    include/p0f/fp_mtu.h
    include/p0f/util.h
    include/p0f/hash.h
    include/p0f/api.h
    readfp.cpp
)

target_compile_definitions(p0f-engine 
	PUBLIC -DVERSION=\"3.09b\" -D_GNU_SOURCE -DDEBUG_BUILD
)

target_include_directories(p0f-engine 
PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(p0f-engine
PUBLIC
)

target_compile_options(p0f-engine
	PUBLIC -Wall -W -Wuseless-cast -Wold-style-cast -pedantic -Wshadow -Wpointer-arith -Wundef -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wfloat-equal -Wformat-extra-args -Wformat-security -Wformat-y2k -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmultichar -Wparentheses -Wreturn-type -Wsequence-point -Wshadow -Wsign-compare -Wswitch -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value  -Wunused-variable -Wwrite-strings -Wcast-align  -Wextra -Wattributes -Wendif-labels -Winit-self -Wint-to-pointer-cast -Winvalid-pch -Wmissing-field-initializers -Wnonnull -Woverflow -Wvla -Wstrict-aliasing -Wvariadic-macros -Wvolatile-register-var -Wmissing-include-dirs -Wmissing-declarations -Wformat=2  -Wno-error -Wno-missing-field-initializers -Wno-redundant-decls -Wno-undef
)

set_property(TARGET p0f-engine PROPERTY CXX_STANDARD 14)
set_property(TARGET p0f-engine PROPERTY CXX_EXTENSIONS OFF)


