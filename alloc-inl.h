/*
   p0f - error-checking, memory-zeroing alloc routines
   ---------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_ALLOC_INL_H_
#define HAVE_ALLOC_INL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "types.h"

#define ALLOC_MAGIC 0xFF00
#define ALLOC_MAGIC_F 0xFE00

#define ALLOC_C(_ptr) (((uint16_t *)(_ptr))[-3])
#define ALLOC_S(_ptr) (((uint32_t *)(_ptr))[-1])

#define CP(_p) (_p)

static inline void *DFL_ck_alloc(uint32_t size) {
	if (!size) return NULL;
	return calloc(size, 1);
}

static inline void *DFL_ck_realloc(void *orig, uint32_t size) {
	return realloc(orig, size);
}

static inline void *DFL_ck_realloc_kb(void *orig, uint32_t size) {
	return DFL_ck_realloc(orig, size);
}

static inline uint8_t *DFL_ck_strdup(uint8_t *str) {
	uint32_t size;

	if (!str) return NULL;

	size = strlen((char *)str) + 1;

	void *ret = calloc(size, 1);
	return memcpy(ret, str, size);
}

static inline void *DFL_ck_memdup(void *mem, uint32_t size) {

	if (!mem || !size) return NULL;
	void *ret = calloc(size, 1);
	return memcpy(ret, mem, size);
}

static inline uint8_t *DFL_ck_memdup_str(uint8_t *mem, uint32_t size) {
	uint8_t *ret;

	if (!mem || !size) return NULL;

	ret = calloc(size + 1, 1);

	memcpy(ret, mem, size);
	ret[size] = 0;

	return ret;
}

#ifndef DEBUG_BUILD

/* Non-debugging mode - straightforward aliasing. */

#define ck_alloc DFL_ck_alloc
#define ck_realloc DFL_ck_realloc
#define ck_realloc_kb DFL_ck_realloc_kb
#define ck_strdup DFL_ck_strdup
#define ck_memdup DFL_ck_memdup
#define ck_memdup_str DFL_ck_memdup_str
#define ck_free DFL_ck_free

#else

/* Debugging mode - include additional structures and support code. */

#define ALLOC_BUCKETS 4096
#define ALLOC_TRK_CHUNK 256

struct TRK_obj {
	void *ptr;
	char *file, *func;
	uint32_t line;
};

extern struct TRK_obj *TRK[ALLOC_BUCKETS];
extern uint32_t TRK_cnt[ALLOC_BUCKETS];

#define TRKH(_ptr) (((((size_t)(_ptr)) >> 16) ^ ((size_t)(_ptr))) % ALLOC_BUCKETS)

/* Adds a new entry to the list of allocated objects. */

static inline void TRK_alloc_buf(void *ptr, const char *file, const char *func,
								 uint32_t line) {

	uint32_t i;
	size_t bucket;

	if (!ptr) return;

	bucket = TRKH(ptr);

	for (i = 0; i < TRK_cnt[bucket]; i++)

		if (!TRK[bucket][i].ptr) {

			TRK[bucket][i].ptr  = ptr;
			TRK[bucket][i].file = (char *)file;
			TRK[bucket][i].func = (char *)func;
			TRK[bucket][i].line = line;
			return;
		}

	/* No space available. */

	if (!(i % ALLOC_TRK_CHUNK)) {

		TRK[bucket] = DFL_ck_realloc(TRK[bucket],
									 (TRK_cnt[bucket] + ALLOC_TRK_CHUNK) * sizeof(struct TRK_obj));
	}

	TRK[bucket][i].ptr  = ptr;
	TRK[bucket][i].file = (char *)file;
	TRK[bucket][i].func = (char *)func;
	TRK[bucket][i].line = line;

	TRK_cnt[bucket]++;
}

/* Removes entry from the list of allocated objects. */

static inline void TRK_free_buf(void *ptr, const char *file, const char *func,
								uint32_t line) {

	uint32_t i, bucket;

	if (!ptr) return;

	bucket = TRKH(ptr);

	for (i = 0; i < TRK_cnt[bucket]; i++)

		if (TRK[bucket][i].ptr == ptr) {

			TRK[bucket][i].ptr = 0;
			return;
		}

	WARN("ALLOC: Attempt to free non-allocated memory in %s (%s:%u)",
		 func, file, line);
}

/* Does a final report on all non-deallocated objects. */

static inline void TRK_report(void) {

	uint32_t i, bucket;

	fflush(0);

	for (bucket = 0; bucket < ALLOC_BUCKETS; bucket++)
		for (i = 0; i < TRK_cnt[bucket]; i++)
			if (TRK[bucket][i].ptr)
				WARN("ALLOC: Memory never freed, created in %s (%s:%u)",
					 TRK[bucket][i].func, TRK[bucket][i].file, TRK[bucket][i].line);
}

/* Simple wrappers for non-debugging functions: */

static inline void *TRK_ck_alloc(uint32_t size, const char *file, const char *func,
								 uint32_t line) {

	void *ret = DFL_ck_alloc(size);
	TRK_alloc_buf(ret, file, func, line);
	return ret;
}

static inline void *TRK_ck_realloc(void *orig, uint32_t size, const char *file,
								   const char *func, uint32_t line) {

	void *ret = DFL_ck_realloc(orig, size);
	TRK_free_buf(orig, file, func, line);
	TRK_alloc_buf(ret, file, func, line);
	return ret;
}

static inline void *TRK_ck_realloc_kb(void *orig, uint32_t size, const char *file,
									  const char *func, uint32_t line) {

	void *ret = DFL_ck_realloc_kb(orig, size);
	TRK_free_buf(orig, file, func, line);
	TRK_alloc_buf(ret, file, func, line);
	return ret;
}

static inline void *TRK_ck_strdup(uint8_t *str, const char *file, const char *func,
								  uint32_t line) {

	void *ret = DFL_ck_strdup(str);
	TRK_alloc_buf(ret, file, func, line);
	return ret;
}

static inline void *TRK_ck_memdup(void *mem, uint32_t size, const char *file,
								  const char *func, uint32_t line) {

	void *ret = DFL_ck_memdup(mem, size);
	TRK_alloc_buf(ret, file, func, line);
	return ret;
}

static inline void *TRK_ck_memdup_str(void *mem, uint32_t size, const char *file,
									  const char *func, uint32_t line) {

	void *ret = DFL_ck_memdup_str(mem, size);
	TRK_alloc_buf(ret, file, func, line);
	return ret;
}

static inline void TRK_ck_free(void *ptr, const char *file,
							   const char *func, uint32_t line) {

	TRK_free_buf(ptr, file, func, line);
	free(ptr);
}

/* Alias user-facing names to tracking functions: */

#define ck_alloc(_p1) \
	TRK_ck_alloc(_p1, __FILE__, __func__, __LINE__)

#define ck_realloc(_p1, _p2) \
	TRK_ck_realloc(_p1, _p2, __FILE__, __func__, __LINE__)

#define ck_realloc_kb(_p1, _p2) \
	TRK_ck_realloc_kb(_p1, _p2, __FILE__, __func__, __LINE__)

#define ck_strdup(_p1) \
	TRK_ck_strdup(_p1, __FILE__, __func__, __LINE__)

#define ck_memdup(_p1, _p2) \
	TRK_ck_memdup(_p1, _p2, __FILE__, __func__, __LINE__)

#define ck_memdup_str(_p1, _p2) \
	TRK_ck_memdup_str(_p1, _p2, __FILE__, __func__, __LINE__)

#define ck_free(_p1) \
	TRK_ck_free(_p1, __FILE__, __func__, __LINE__)

#endif /* ^!DEBUG_BUILD */

#define alloc_printf(...) ({                         \
	uint8_t *_tmp;                                   \
	int32_t _len = snprintf(NULL, 0, __VA_ARGS__);   \
	if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
	_tmp = ck_alloc(_len + 1);                       \
	snprintf((char *)_tmp, _len + 1, __VA_ARGS__);   \
	_tmp;                                            \
})

#endif /* ! HAVE_ALLOC_INL_H_ */
