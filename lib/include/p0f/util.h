/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_UTIL_H_
#define HAVE_UTIL_H_

#include "p0f.h"
#include "tcp.h"
#include <ostream>

template <class... T>
void append_format(std::ostream &os, const char *fmt, T &&... args) {
	char *ptr = nullptr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wformat-security"
	if (asprintf(&ptr, fmt, std::forward<T>(args)...) != -1) {
#pragma GCC diagnostic pop
		os << ptr;
		free(ptr);
	}
}

template <class... T>
void observf(libp0f_context_t *libp0f_context, const char *key, const char *fmt, T &&... args) {
	char *ptr = nullptr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wformat-security"
	if (asprintf(&ptr, fmt, std::forward<T>(args)...) != -1) {
#pragma GCC diagnostic pop
		libp0f_context->observation_field(key, ptr);
		free(ptr);
	}
}

// Convert IPv4 or IPv6 address to a human-readable form.
inline char *addr_to_str(uint8_t *data, uint8_t ip_ver) {

	static char tmp[128];

	/* We could be using inet_ntop(), but on systems that have older libc
	 * but still see passing IPv6 traffic, we would be in a pickle. */
	if (ip_ver == IP_VER4) {
		sprintf(tmp, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
	} else {
		sprintf(tmp, "%x:%x:%x:%x:%x:%x:%x:%x",
				(data[0] << 8) | data[1], (data[2] << 8) | data[3],
				(data[4] << 8) | data[5], (data[6] << 8) | data[7],
				(data[8] << 8) | data[9], (data[10] << 8) | data[11],
				(data[12] << 8) | data[13], (data[14] << 8) | data[15]);
	}

	return tmp;
}

#endif
