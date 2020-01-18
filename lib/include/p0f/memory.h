/*
   p0f - type definitions and minor macros
   ---------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_MEMORY_H_
#define HAVE_MEMORY_H_

#include <cstdint>
#include <cstring>

// for non-aligned memory access.
inline uint16_t RD16p(const void *ptr) {
	uint16_t _ret;
	memcpy(&_ret, ptr, 2);
	return _ret;
}

inline uint32_t RD32p(const void *ptr) {
	uint32_t _ret;
	memcpy(&_ret, ptr, 4);
	return _ret;
}

template <class T>
uint16_t RD16(const T &val) {
	static_assert(sizeof(T) >= sizeof(uint16_t), "");
	return RD16p(&val);
}

template <class T>
uint32_t RD32(const T &val) {
	static_assert(sizeof(T) >= sizeof(uint32_t), "");
	return RD32p(&val);
}

#endif
