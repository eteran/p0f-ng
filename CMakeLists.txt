cmake_minimum_required(VERSION 3.0)

project(p0f)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

find_package(PCAP REQUIRED)

option(ENABLE_ASAN          "Enable address santiziers")
option(ENABLE_USAN          "Enable undefined santiziers")
option(ENABLE_MSAN          "Enable memory santiziers")
option(ENABLE_TSAN          "Enable thread santiziers")

if(ENABLE_ASAN)
	set(CMAKE_CXX_FLAGS        "${CMAKE_CXX_FLAGS}        -fsanitize=address") # -fsanitize-address-use-after-scope
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
	add_definitions(-D_GLIBCXX_SANITIZE_VECTOR)
endif()

if(ENABLE_USAN)
	set(CMAKE_CXX_FLAGS        "${CMAKE_CXX_FLAGS}        -fsanitize=undefined")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
endif()

if(ENABLE_TSAN)
	set(CMAKE_CXX_FLAGS        "${CMAKE_CXX_FLAGS}        -fsanitize=thread")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
endif()

if(ENABLE_MSAN)
	set(CMAKE_CXX_FLAGS        "${CMAKE_CXX_FLAGS}        -fsanitize=memory")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=memory")
endif()


add_executable(p0f
	p0f.cpp
)

target_compile_definitions(p0f
	PUBLIC -DVERSION=\"3.09b\" -D_GNU_SOURCE -DDEBUG_BUILD
)

target_compile_options(p0f
	PUBLIC -Wall -W -Wuseless-cast -Wold-style-cast -pedantic -Wshadow -Wpointer-arith -Wundef -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wfloat-equal -Wformat-extra-args -Wformat-security -Wformat-y2k -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmultichar -Wparentheses -Wreturn-type -Wsequence-point -Wshadow -Wsign-compare -Wswitch -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value  -Wunused-variable -Wwrite-strings -Wcast-align  -Wextra -Wattributes -Wendif-labels -Winit-self -Wint-to-pointer-cast -Winvalid-pch -Wmissing-field-initializers -Wnonnull -Woverflow -Wvla -Wstrict-aliasing -Wvariadic-macros -Wvolatile-register-var -Wmissing-include-dirs -Wmissing-declarations -Wformat=2  -Wno-error -Wno-missing-field-initializers -Wno-redundant-decls -Wno-undef
)

target_include_directories(p0f
	PUBLIC ${PCAP_INCLUDE_DIR}
)

target_link_libraries(p0f PUBLIC
	${PCAP_LIBRARIES}
    p0f-engine
)


set_property(TARGET p0f PROPERTY CXX_EXTENSIONS OFF)
set_property(TARGET p0f PROPERTY CXX_STANDARD 14)

add_subdirectory(tools)
add_subdirectory(lib)
