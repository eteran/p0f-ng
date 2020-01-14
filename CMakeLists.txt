cmake_minimum_required(VERSION 3.0)

project(p0f CXX)

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
	alloc-inl.h
	api.cpp
	api.h
	config.h
	debug.h
	fp_http.cpp
	fp_http.h
	fp_mtu.cpp
	fp_mtu.h
	fp_tcp.cpp
	fp_tcp.h
	hash.h
	languages.h
	p0f.cpp
	p0f.h
	process.cpp
	process.h
	readfp.cpp
	readfp.h
	tcp.h
	types.h
)

target_compile_definitions(p0f
	PUBLIC -DVERSION=\"3.09b\" -DALIGN_ACCESS -D_GNU_SOURCE -DDEBUG_BUILD
)

target_compile_options(p0f
	PUBLIC -W -Wall
)

target_include_directories(p0f
	PUBLIC ${PCAP_INCLUDE_DIR}
)

target_link_libraries(p0f PUBLIC
	${PCAP_LIBRARIES}
)


set_property(TARGET p0f PROPERTY CXX_EXTENSIONS ON)
set_property(TARGET p0f PROPERTY CXX_STANDARD 14)


