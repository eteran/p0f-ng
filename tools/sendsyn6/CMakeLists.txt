cmake_minimum_required(VERSION 3.0)

add_executable(p0f-sendsyn6 
	p0f-sendsyn6.cpp
)

target_compile_options(p0f-sendsyn6
PUBLIC
	-Wall -Wno-format -funsigned-char
)

target_link_libraries(p0f-sendsyn6
PUBLIC
    p0f-engine
)

set_property(TARGET p0f-sendsyn6 PROPERTY RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
