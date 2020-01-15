cmake_minimum_required(VERSION 3.0)

add_executable(p0f-client 
	p0f-client.cpp
)

target_compile_options(p0f-client 
PUBLIC
	-Wall -Wno-format -funsigned-char
)

target_link_libraries(p0f-client
PUBLIC
    p0f-engine
)

set_property(TARGET p0f-client PROPERTY RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
