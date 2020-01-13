cmake_minimum_required(VERSION 3.0)

project(p0f C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

find_package(PCAP REQUIRED)

add_executable(p0f
	alloc-inl.h
	api.c
	api.h
	config.h
	debug.h
	fp_http.c
	fp_http.h
	fp_mtu.c
	fp_mtu.h
	fp_tcp.c
	fp_tcp.h
	hash.h
	languages.h
	p0f.c
	p0f.h
	process.c
	process.h
	readfp.c
	readfp.h
	tcp.h
	types.h
)

target_compile_definitions(p0f
	PUBLIC -DVERSION=\"3.09b\")

target_compile_options(p0f
	PUBLIC -W -Wall -pedantic
)

target_include_directories(p0f
	PUBLIC ${PCAP_INCLUDE_DIR}
)

target_link_libraries(p0f PUBLIC
	${PCAP_LIBRARIES}
)


set_property(TARGET p0f PROPERTY C_EXTENSIONS ON)
set_property(TARGET p0f PROPERTY C_STANDARD 99)


