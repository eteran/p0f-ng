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

inline uint8_t *DFL_ck_strdup(const uint8_t *str) {
	uint32_t size;

	if (!str) return nullptr;

	size = strlen((char *)str) + 1;

	void *ret = calloc(size, 1);
	return (uint8_t *)memcpy(ret, str, size);
}

inline void *DFL_ck_memdup(const void *mem, uint32_t size) {

	if (!mem || !size) return nullptr;
	void *ret = calloc(size, 1);
	return memcpy(ret, mem, size);
}

inline uint8_t *DFL_ck_memdup_str(const uint8_t *mem, uint32_t size) {
	uint8_t *ret;

	if (!mem || !size) return nullptr;

	ret = (uint8_t *)calloc(size + 1, 1);

	memcpy(ret, mem, size);
	ret[size] = 0;

	return ret;
}

#define ck_strdup DFL_ck_strdup
#define ck_memdup DFL_ck_memdup
#define ck_memdup_str DFL_ck_memdup_str

#endif /* ! HAVE_ALLOC_INL_H_ */
