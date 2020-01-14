/*
   p0f - exports from the main routine
   -----------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_P0F_H_
#define HAVE_P0F_H_

#include "process.h"
#include "types.h"
#include <ostream>

extern uint8_t daemon_mode;
extern int32_t link_type;
extern uint32_t max_conn;
extern uint32_t max_hosts;
extern uint32_t conn_max_age;
extern uint32_t host_idle_limit;
extern char *read_file;

void start_observation(const char *keyword, uint8_t field_cnt, uint8_t to_srv, const packet_flow *pf);
void add_observation_field(const char *key, const char *value);

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
void observf(const char *key, const char *fmt, T &&... args) {
	char *ptr = nullptr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wformat-security"
	if (asprintf(&ptr, fmt, std::forward<T>(args)...) != -1) {
#pragma GCC diagnostic pop
		add_observation_field(key, ptr);
		free(ptr);
	}
}

#include "api.h"

struct api_client {

	int32_t fd; /* -1 if slot free                    */

	struct p0f_api_query in_data; /* Query recv buffer                  */
	uint32_t in_off;              /* Query buffer offset                */

	struct p0f_api_response out_data; /* Response transmit buffer           */
	uint32_t out_off;                 /* Response buffer offset             */
};

#endif /* !HAVE_P0F_H_ */
