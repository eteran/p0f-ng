/*
   p0f - exports from the main routine
   -----------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_P0F_H_
#define HAVE_P0F_H_

#include "process.h"
#include <cstdint>
#include <vector>

struct libp0f_context_t {
	using observation_begin_t = void (*)(const char *, uint8_t, bool, const packet_flow *);
	using observation_field_t = void (*)(const char *, const char *);

	// Observation hooks
	observation_begin_t start_observation = [](const char *, uint8_t, bool, const packet_flow *) {};
	observation_field_t observation_field = [](const char *, const char *) {};

	// Fill in by the one driving things
	const char *read_file    = nullptr;         // File to read pcap data from
	uint32_t max_conn        = MAX_CONN;        // Connection entry count limit
	uint32_t max_hosts       = MAX_HOSTS;       // Host cache entry count limit
	uint32_t conn_max_age    = CONN_MAX_AGE;    // Maximum age of a connection entry
	uint32_t host_idle_limit = HOST_IDLE_LIMIT; // Host cache idle timeout
	int32_t link_type        = 0;               // PCAP link type

	// Results
	uint64_t packet_cnt = 0; // Total number of packets processed
};

#endif
