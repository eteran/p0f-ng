cmake_minimum_required(VERSION 3.0)

add_executable(p0f-sendsyn 
	p0f-sendsyn.cpp
)

target_compile_options(p0f-sendsyn 
PUBLIC
    -pedantic
    -Wall
    -W
)

target_link_libraries(p0f-sendsyn
PUBLIC
	p0f-engine
)

set_property(TARGET p0f-sendsyn PROPERTY RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
