/*
   p0f - error-checking, memory-zeroing alloc routines
   ---------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_ALLOC_INL_H_
#define HAVE_ALLOC_INL_H_

#include <cstdlib>
#include <cstring>

inline char *ck_strdup(const char *str) {
	if (!str)
		return nullptr;

	size_t size = strlen(str) + 1;
	void *ret   = malloc(size);
	return static_cast<char *>(memcpy(ret, str, size));
}

#endif
