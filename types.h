/*
   p0f - type definitions and minor macros
   ---------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_TYPES_H_
#define HAVE_TYPES_H_

#include <stdint.h>

#ifndef MIN
#define MIN(_a, _b) ((_a) > (_b) ? (_b) : (_a))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

/* Macros for non-aligned memory access. */

#ifdef ALIGN_ACCESS
#include <string.h>

static inline uint16_t RD16p(const void *ptr) {
	uint16_t _ret;
	memcpy(&_ret, ptr, 2);
	return _ret;
}

static inline uint32_t RD32p(const void *ptr) {
	uint32_t _ret;
	memcpy(&_ret, ptr, 4);
	return _ret;
}

#define RD16(_val) RD16p(&_val)
#define RD32(_val) RD32p(&_val)

#else
#define RD16(_val) ((uint16_t)_val)
#define RD32(_val) ((uint32_t)_val)
#define RD16p(_ptr) (*((uint16_t *)(_ptr)))
#define RD32p(_ptr) (*((uint32_t *)(_ptr)))
#endif /* ^ALIGN_ACCESS */

#endif /* ! _HAVE_TYPES_H */
