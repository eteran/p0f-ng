/*
   p0f - error-checking, memory-zeroing alloc routines
   ---------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_ALLOC_INL_H_
#define HAVE_ALLOC_INL_H_

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "types.h"

inline char *ck_strdup(const char *str) {
	if (!str)
		return nullptr;

	size_t size = strlen(str) + 1;
	void *ret   = malloc(size);
	return static_cast<char *>(memcpy(ret, str, size));
}

inline void *ck_memdup(const void *mem, uint32_t size) {

	if (!mem || !size)
		return nullptr;

	void *ret = malloc(size);
	return memcpy(ret, mem, size);
}

inline char *ck_memdup_str(const char *mem, uint32_t size) {

	if (!mem || !size)
		return nullptr;

	auto ret = static_cast<char *>(malloc(size + 1));
	memcpy(ret, mem, size);
	ret[size] = 0;
	return ret;
}

#endif // ! HAVE_ALLOC_INL_H_
