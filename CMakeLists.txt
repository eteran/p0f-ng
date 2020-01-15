cmake_minimum_required(VERSION 3.0)

project(p0f)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

find_package(PCAP REQUIRED)

option(ENABLE_ASAN          "Enable address santiziers")
option(ENABLE_USAN          "Enable undefined santiziers")
option(ENABLE_MSAN          "Enable memory santiziers")
option(ENABLE_TSAN          "Enable thread santiziers")
option(P0F_BUILD_TOOLS      "Build example tools")

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

add_subdirectory(lib)
add_subdirectory(src)

if(P0F_BUILD_TOOLS)
	add_subdirectory(tools)
endif()
