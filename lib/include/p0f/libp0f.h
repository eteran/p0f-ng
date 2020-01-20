/*
   p0f - exports from the main routine
   -----------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_LIB_P0F_H_
#define HAVE_LIB_P0F_H_

#include "fp_mtu.h"
#include "process.h"
#include "readfp.h"
#include <cstdint>
#include <vector>

struct p0f_api_query;
struct p0f_api_response;

enum class Alert {
	TooManyHosts,
	TooManyConnections,
};

struct libp0f_settings {
	uint32_t max_conn        = MAX_CONN;        // Connection entry count limit
	uint32_t max_hosts       = MAX_HOSTS;       // Host cache entry count limit
	uint32_t conn_max_age    = CONN_MAX_AGE;    // Maximum age of a connection entry
	uint32_t host_idle_limit = HOST_IDLE_LIMIT; // Host cache idle timeout
	int link_type            = 0;               // PCAP link type
};

struct libp0f {
	friend struct http_context_t;
	friend struct mtu_context_t;
	friend struct tcp_context_t;
	friend struct process_context_t;
	friend struct fp_context_t;

public:
	libp0f(const char *filename);
	libp0f(const char *filename, const libp0f_settings &new_settings);
	virtual ~libp0f();

public:
	void handle_query(const p0f_api_query *q, p0f_api_response *r);
	void parse_packet_frame(struct timeval ts, const uint8_t *data, size_t packet_len);

public:
	// Observation hooks
	virtual void start_observation(time_t time, const char *keyword, uint8_t field_cnt, bool to_srv, const packet_flow *f) {
		(void)time;
		(void)keyword;
		(void)field_cnt;
		(void)to_srv;
		(void)f;
	}

	virtual void observation_field(const char *key, const char *value) {
		(void)key;
		(void)value;
	}

	virtual void alert(Alert alert, uint32_t count) {
		(void)alert;
		(void)count;
	}
private:
	void begin_observation(const char *keyword, uint8_t field_cnt, bool to_srv, const packet_flow *f);


public:
	// Results
	uint64_t packet_cnt = 0; // Total number of packets processed

private:
	http_context_t http_context{this};
	mtu_context_t mtu_context{this};
	tcp_context_t tcp_context{this};
	process_context_t process_context{this};
	fp_context_t fp_context{this};
	libp0f_settings settings;
};

#endif
