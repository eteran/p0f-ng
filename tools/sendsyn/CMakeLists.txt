cmake_minimum_required(VERSION 3.0)


add_executable(p0f-sendsyn 
	p0f-sendsyn.cpp
)

target_compile_options(p0f-sendsyn 
PUBLIC
	-Wall -Wno-format -funsigned-char
)

target_link_libraries(p0f-sendsyn
PUBLIC
    p0f-engine
)
