/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_API_CLIENT_H_
#define HAVE_API_CLIENT_H_

#include "api.h"

struct api_client {

	int32_t fd; // -1 if slot free

	p0f_api_query in_data; // Query recv buffer
	uint32_t in_off;       // Query buffer offset

	p0f_api_response out_data; // Response transmit buffer
	uint32_t out_off;          // Response buffer offset
};

#endif
