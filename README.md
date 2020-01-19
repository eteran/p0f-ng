# p0f-ng

[p0f](http://lcamtuf.coredump.cx/p0f3/) is a wonderful tool. Unfortunately,
because of some of the core design decisions, specifically it being a service 
with a socket API, it proves very difficult to use as a library.

This project aims to bring p0f into the modern age.

It has been ported to C++, it no longer uses any compiler extensions beyond
structure packing, and functions as a true library which can be built into
any C++ project easily.

Additionally, the build system has been updated to use CMake.

For proof of concept, the original p0f service is still available and is just
built in terms of the new library API.
