/*
   p0f - exports from the main routine
   -----------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_P0F_H
#define _HAVE_P0F_H

#include "process.h"
#include "types.h"

extern uint8_t daemon_mode;
extern int32_t link_type;
extern uint32_t max_conn, max_hosts, conn_max_age, host_idle_limit;
extern uint8_t *read_file;

void start_observation(char *keyword, uint8_t field_cnt, uint8_t to_srv,
					   struct packet_flow *pf);

void add_observation_field(char *key, uint8_t *value);

#define OBSERVF(_key, ...)                        \
	do {                                          \
		char *_val;                               \
		if (asprintf(&_val, __VA_ARGS__) != -1) { \
			add_observation_field(_key, _val);    \
			free(_val);                           \
		}                                         \
	} while (0)

#include "api.h"

struct api_client {

	int32_t fd; /* -1 if slot free                    */

	struct p0f_api_query in_data; /* Query recv buffer                  */
	uint32_t in_off;              /* Query buffer offset                */

	struct p0f_api_response out_data; /* Response transmit buffer           */
	uint32_t out_off;                 /* Response buffer offset             */
};

#endif /* !_HAVE_P0F_H */
