/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_FP_HTTP_H_
#define HAVE_FP_HTTP_H_

#include "config.h"
#include "string_view.h"
#include <cstdint>
#include <ctime>
#include <memory>
#include <vector>

struct packet_flow;
struct libp0f_context_t;

// A structure used for looking up various headers internally in fp_http.c:
struct http_id {
	const char *name;
	int32_t id;
};

// Another internal structure for UA -> OS maps:
struct ua_map_record {
	const char *name;
	int32_t id;
};

// HTTP header field:
struct http_hdr {
	char *name    = nullptr; // Text name (nullptr = use lookup ID)
	char *value   = nullptr; // Value, if any
	int32_t id    = 0;       // Lookup ID (-1 = none)
	bool optional = false;   // Optional header?
};

// Request / response signature collected from the wire:
struct http_sig {

	int8_t http_ver = 0; // HTTP version (-1 = any)

	std::vector<struct http_hdr> hdr; // Mandatory / discovered headers

	uint64_t hdr_bloom4 = 0; // Bloom filter for headers

	int32_t miss[HTTP_MAX_HDRS] = {}; // Missing headers
	uint32_t miss_cnt           = 0;

	char *sw         = nullptr; // Software string (U-A or Server)
	const char *lang = nullptr; // Accept-Language
	const char *via  = nullptr; // Via or X-Forwarded-For

	time_t date      = 0; // Parsed 'Date'
	time_t recv_date = 0; // Actual receipt date

	// Information used for matching with p0f.fp:

	struct http_sig_record *matched = nullptr; // nullptr = no match
	uint8_t dishonest               = 0;       // "sw" looks forged?
};

// Record for a HTTP signature read from p0f.fp:
struct http_sig_record {

	int32_t class_id;   // OS class ID (-1 = user)
	int32_t name_id;    // OS name ID
	const char *flavor; // Human-readable flavor string

	int32_t label_id; // Signature label ID

	uint32_t *sys;    // OS class / name IDs for user apps
	uint32_t sys_cnt; // Length of sys

	uint32_t line_no; // Line number in p0f.fp

	uint8_t generic; // Generic signature?

	std::unique_ptr<struct http_sig> sig; // Actual signature data
};

void http_parse_ua(string_view val, uint32_t line_no);
void http_register_sig(bool to_srv, uint8_t generic, int32_t sig_class, int32_t sig_name, char *sig_flavor, int32_t label_id, uint32_t *sys, uint32_t sys_cnt, string_view val, uint32_t line_no);
bool process_http(bool to_srv, struct packet_flow *f, libp0f_context_t *libp0f_context);
void free_sig_hdrs(struct http_sig *h);
void http_init();

#endif
