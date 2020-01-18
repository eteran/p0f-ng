/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_FP_HTTP_H_
#define HAVE_FP_HTTP_H_

#include "config.h"
#include "config_http.h"
#include "ext/optional.h"
#include "ext/string_view.h"
#include <cstdint>
#include <ctime>
#include <memory>
#include <vector>

struct packet_flow;
struct libp0f_context_t;
struct http_sig_record;

// Another internal structure for UA -> OS maps:
struct ua_map_record {
	std::string name;
	int32_t id;
};

// HTTP header field:
struct http_hdr {
	ext::optional<std::string> name;  // Text name (nullptr = use lookup ID)
	ext::optional<std::string> value; // Value, if any
	int32_t id    = 0;                // Lookup ID (-1 = none)
	bool optional = false;            // Optional header?
};

// Request / response signature collected from the wire:
struct http_sig {

	int8_t http_ver = 0; // HTTP version (-1 = any)

	std::vector<http_hdr> hdr; // Mandatory / discovered headers

	uint64_t hdr_bloom4 = 0; // Bloom filter for headers

	std::vector<int32_t> miss; // Missing headers

	ext::optional<std::string> sw;   // Software string (U-A or Server)
	ext::optional<std::string> lang; // Accept-Language
	ext::optional<std::string> via;  // Via or X-Forwarded-For

	time_t date      = 0; // Parsed 'Date'
	time_t recv_date = 0; // Actual receipt date

	// Information used for matching with p0f.fp:

	http_sig_record *matched = nullptr; // nullptr = no match
	uint8_t dishonest        = 0;       // "sw" looks forged?
};

// Record for a HTTP signature read from p0f.fp:
struct http_sig_record {

	int32_t class_id = 0;              // OS class ID (-1 = user)
	int32_t name_id  = 0;              // OS name ID
	ext::optional<std::string> flavor; // Human-readable flavor string

	int32_t label_id = 0; // Signature label ID

	std::vector<uint32_t> sys; // OS class / name IDs for user apps

	uint32_t line_no = 0; // Line number in p0f.fp
	uint8_t generic  = 0; // Generic signature?

	std::unique_ptr<http_sig> sig; // Actual signature data
};

struct http_context_t {
public:
	http_context_t();

public:
	bool process_http(bool to_srv, packet_flow *f, libp0f_context_t *libp0f_context);
	void http_parse_ua(ext::string_view value, uint32_t line_no);
	void http_register_sig(bool to_srv, uint8_t generic, int32_t sig_class, int32_t sig_name, const ext::optional<std::string> &sig_flavor, int32_t label_id, const std::vector<uint32_t> &sys, ext::string_view value, uint32_t line_no);

private:
	int32_t lookup_hdr(const std::string &name, bool create);
	void http_find_match(bool to_srv, http_sig *ts, uint8_t dupe_det);
	void http_find_match(bool to_srv, const std::unique_ptr<http_sig> &ts, uint8_t dupe_det);
	std::string dump_sig(bool to_srv, const http_sig *hsig);
	void score_nat(bool to_srv, const packet_flow *f, libp0f_context_t *libp0f_context);
	void fingerprint_http(bool to_srv, packet_flow *f, libp0f_context_t *libp0f_context);
	bool parse_pairs(bool to_srv, packet_flow *f, bool can_get_more, libp0f_context_t *libp0f_context);
	std::string dump_flags(const http_sig *hsig, const http_sig_record *m);

private:
	http_id req_optional_[sizeof(req_optional_init) / sizeof(http_id)];
	http_id resp_optional_[sizeof(resp_optional_init) / sizeof(http_id)];
	http_id req_common_[sizeof(req_common_init) / sizeof(http_id)];
	http_id resp_common_[sizeof(resp_common_init) / sizeof(http_id)];
	http_id req_skipval_[sizeof(req_skipval_init) / sizeof(http_id)];
	http_id resp_skipval_[sizeof(resp_skipval_init) / sizeof(http_id)];

	std::vector<std::string> hdr_names_;             // List of header names by ID
	std::vector<uint32_t> hdr_by_hash_[SIG_BUCKETS]; // Hashed header names

	/* Signatures aren't bucketed due to the complex matching used; but we use
	 * Bloom filters to go through them quickly. */
	std::vector<http_sig_record> sigs_[2];

	std::vector<ua_map_record> ua_map_; // Mappings between U-A and OS
};

extern http_context_t http_context;

#endif
