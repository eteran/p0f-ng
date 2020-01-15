/*
   p0f - type definitions and minor macros
   ---------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_TYPES_H_
#define HAVE_TYPES_H_

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

#define RD16(_val) RD16p(&_val)
#define RD32(_val) RD32p(&_val)

#endif // ! _HAVE_TYPES_H
