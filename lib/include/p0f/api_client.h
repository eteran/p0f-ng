/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef P0F_API_CLIENT_H_
#define P0F_API_CLIENT_H_

#include "api.h"
#include <cstddef>

struct api_client {

	int fd; // -1 if slot free

	p0f_api_query in_data; // Query recv buffer
	size_t in_off;         // Query buffer offset

	p0f_api_response out_data; // Response transmit buffer
	size_t out_off;            // Response buffer offset
};

#endif
