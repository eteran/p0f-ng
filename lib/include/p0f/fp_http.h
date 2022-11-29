/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef P0F_FP_HTTP_H_
#define P0F_FP_HTTP_H_

#include "config.h"
#include "config_http.h"
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <vector>

struct packet_flow;
struct libp0f;
struct http_sig_record;

// Another internal structure for UA -> OS maps:
struct ua_map_record {
	std::string name;
	uint32_t id;
};

// HTTP header field:
struct http_hdr {
	std::optional<std::string> name;  // Text name (nullptr = use lookup ID)
	std::optional<std::string> value; // Value, if any
	uint32_t id   = 0;                // Lookup ID (-1 = none)
	bool optional = false;            // Optional header?
};

// Request / response signature collected from the wire:
struct http_sig {

	int8_t http_ver = 0; // HTTP version (-1 = any)

	std::vector<http_hdr> hdr; // Mandatory / discovered headers

	uint64_t hdr_bloom4 = 0; // Bloom filter for headers

	std::vector<uint32_t> miss; // Missing headers

	std::optional<std::string> sw;   // Software string (U-A or Server)
	std::optional<std::string> lang; // Accept-Language
	std::optional<std::string> via;  // Via or X-Forwarded-For

	time_t date      = 0; // Parsed 'Date'
	time_t recv_date = 0; // Actual receipt date

	// Information used for matching with p0f.fp:

	http_sig_record *matched = nullptr; // nullptr = no match
	uint8_t dishonest        = 0;       // "sw" looks forged?
};

// Record for a HTTP signature read from p0f.fp:
struct http_sig_record {

	uint32_t class_id = 0;             // OS class ID (-1 = user)
	uint32_t name_id  = 0;             // OS name ID
	std::optional<std::string> flavor; // Human-readable flavor string

	uint32_t label_id = 0; // Signature label ID

	std::vector<uint32_t> sys; // OS class / name IDs for user apps

	uint32_t line_no = 0; // Line number in p0f.fp
	uint8_t generic  = 0; // Generic signature?

	std::unique_ptr<http_sig> sig; // Actual signature data
};

struct http_context_t {
public:
	http_context_t(libp0f *ctx);

public:
	bool process_http(bool to_srv, packet_flow *f);
	void http_parse_ua(std::string_view value, uint32_t line_no);
	void http_register_sig(bool to_srv, uint8_t generic, uint32_t sig_class, uint32_t sig_name, const std::optional<std::string> &sig_flavor, uint32_t label_id, const std::vector<uint32_t> &sys, std::string_view value, uint32_t line_no);

private:
	uint32_t lookup_hdr(const std::string &name, bool create);
	void http_find_match(bool to_srv, http_sig *ts, uint8_t dupe_det);
	void http_find_match(bool to_srv, const std::unique_ptr<http_sig> &ts, uint8_t dupe_det);
	std::string dump_sig(bool to_srv, const http_sig *hsig);
	void score_nat(bool to_srv, const packet_flow *f);
	void fingerprint_http(bool to_srv, packet_flow *f);
	bool parse_pairs(bool to_srv, packet_flow *f, bool can_get_more);

private:
	http_id req_optional_[sizeof(req_optional_init) / sizeof(http_id)];
	http_id resp_optional_[sizeof(resp_optional_init) / sizeof(http_id)];
	http_id req_common_[sizeof(req_common_init) / sizeof(http_id)];
	http_id resp_common_[sizeof(resp_common_init) / sizeof(http_id)];
	http_id req_skipval_[sizeof(req_skipval_init) / sizeof(http_id)];
	http_id resp_skipval_[sizeof(resp_skipval_init) / sizeof(http_id)];

	// lookup a header by ID or name
	std::unordered_map<uint32_t, std::string> hdr_names_; // header names by ID
	std::unordered_map<std::string, uint32_t> hdr_ids_;   // header IDs by name

	/* Signatures aren't bucketed due to the complex matching used; but we use
	 * Bloom filters to go through them quickly. */
	std::vector<http_sig_record> sigs_[2];

	std::vector<ua_map_record> ua_map_; // Mappings between U-A and OS
private:
	libp0f *ctx_ = nullptr;
};

#endif
