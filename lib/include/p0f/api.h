/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef P0F_API_H_
#define P0F_API_H_

#include "ip_address.h"
#include <cstdint>
#include <ctime>

constexpr uint32_t P0F_QUERY_MAGIC = 0x50304601;
constexpr uint32_t P0F_RESP_MAGIC  = 0x50304602;

constexpr uint8_t P0F_STATUS_BADQUERY = 0x00;
constexpr uint8_t P0F_STATUS_OK       = 0x10;
constexpr uint8_t P0F_STATUS_NOMATCH  = 0x20;

constexpr uint8_t P0F_ADDR_IPV4 = 0x04;
constexpr uint8_t P0F_ADDR_IPV6 = 0x06;

constexpr int P0F_STR_MAX = 31;

constexpr uint8_t P0F_MATCH_FUZZY   = 0x01;
constexpr uint8_t P0F_MATCH_GENERIC = 0x02;

// Keep these structures aligned to avoid architecture-specific padding.
struct p0f_api_query {
	uint32_t magic;    // Must be P0F_QUERY_MAGIC
	uint8_t addr_type; // P0F_ADDR_*
	uint8_t reserved[3];
	ip_address addr; // IP address (big endian left align)
};

struct p0f_api_response {
	uint32_t magic;  // Must be P0F_RESP_MAGIC
	uint32_t status; // P0F_STATUS_*

	time_t first_seen;   // First seen (unix time)
	time_t last_seen;    // Last seen (unix time)
	uint32_t total_conn; // Total connections seen

	uint32_t uptime_min;  // Last uptime (minutes)
	uint32_t up_mod_days; // Uptime modulo (days)

	time_t last_nat; // NAT / LB last detected (unix time)
	time_t last_chg; // OS chg last detected (unix time)

	int16_t distance; // System distance

	uint8_t bad_sw;     // Host is lying about U-A / Server
	uint8_t os_match_q; // Match quality

	char os_name[P0F_STR_MAX + 1];     // Name of detected OS
	char os_flavor[P0F_STR_MAX + 1];   // Flavor of detected OS
	char http_name[P0F_STR_MAX + 1];   // Name of detected HTTP app
	char http_flavor[P0F_STR_MAX + 1]; // Flavor of detected HTTP app
	char link_type[P0F_STR_MAX + 1];   // Link type
	char language[P0F_STR_MAX + 1];    // Language
};

#endif
