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

inline uint8_t *ck_strdup(const uint8_t *str) {
	if (!str)
		return nullptr;

	size_t size = strlen((char *)str) + 1;
	void *ret   = malloc(size);
	return (uint8_t *)memcpy(ret, str, size);
}

inline void *ck_memdup(const void *mem, uint32_t size) {

	if (!mem || !size)
		return nullptr;

	void *ret = malloc(size);
	return memcpy(ret, mem, size);
}

inline uint8_t *ck_memdup_str(const uint8_t *mem, uint32_t size) {

	if (!mem || !size)
		return nullptr;

	uint8_t *ret = (uint8_t *)malloc(size + 1);
	memcpy(ret, mem, size);
	ret[size] = 0;
	return ret;
}

#endif /* ! HAVE_ALLOC_INL_H_ */
