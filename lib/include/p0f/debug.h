/*
   p0f - debug / error handling macros
   -----------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_DEBUG_H_
#define HAVE_DEBUG_H_

#include "config.h"

#ifdef DEBUG_BUILD
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...) \
	do {           \
	} while (0)
#endif

#define ERRORF(...) fprintf(stderr, __VA_ARGS__)
#define SAYF(...)   printf(__VA_ARGS__)

#define WARN(...)                            \
	do {                                     \
		ERRORF("[!] WARNING: " __VA_ARGS__); \
		ERRORF("\n");                        \
	} while (0)

#define FATAL(...)                                      \
	do {                                                \
		ERRORF("[-] PROGRAM ABORT : " __VA_ARGS__);     \
		ERRORF("\n         Location : %s(), %s:%d\n\n", \
			   __func__, __FILE__, __LINE__);           \
		exit(1);                                        \
	} while (0)

#define ABORT(...)                                      \
	do {                                                \
		ERRORF("[-] PROGRAM ABORT : " __VA_ARGS__);     \
		ERRORF("\n         Location : %s(), %s:%d\n\n", \
			   __func__, __FILE__, __LINE__);           \
		abort();                                        \
	} while (0)

#define PFATAL(...)                                  \
	do {                                             \
		ERRORF("[-] SYSTEM ERROR : " __VA_ARGS__);   \
		ERRORF("\n        Location : %s(), %s:%d\n", \
			   __func__, __FILE__, __LINE__);        \
		perror("      OS message ");                 \
		ERRORF("\n");                                \
		exit(1);                                     \
	} while (0)

#endif
