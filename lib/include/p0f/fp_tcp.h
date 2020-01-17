/*
   p0f - TCP/IP packet matching
   ----------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_FP_TCP_H_
#define HAVE_FP_TCP_H_

#include "optional.h"
#include "string_view.h"
#include <cstdint>
#include <memory>
#include <vector>

// Simplified data for signature matching and NAT detection:
struct tcp_sig {

	uint32_t opt_hash = 0; // Hash of opt_layout
	uint32_t quirks   = 0; // Quirks

	uint8_t opt_eol_pad = 0; // Amount of padding past EOL
	uint8_t ip_opt_len  = 0; // Length of IP options

	int8_t ip_ver = 0; // -1 = any, IP_VER4, IP_VER6

	uint8_t ttl = 0; // Actual TTL

	int32_t mss      = 0; // Maximum segment size (-1 = any)
	uint16_t win     = 0; // Window size
	uint8_t win_type = 0; // WIN_TYPE_*
	int16_t wscale   = 0; // Window scale (-1 = any)

	int8_t pay_class = 0; // -1 = any, 0 = zero, 1 = non-zero

	uint16_t tot_hdr = 0; // Total header length
	uint32_t ts1     = 0; // Own timestamp
	uint64_t recv_ms = 0; // Packet recv unix time (ms)

	// Information used for matching with p0f.fp:

	struct tcp_sig_record *matched = nullptr; // nullptr = no match
	uint8_t fuzzy                  = 0;       // Approximate match?
	uint8_t dist                   = 0;       // Distance
};

// Methods for matching window size in tcp_sig:
#define WIN_TYPE_NORMAL 0x00 // Literal value
#define WIN_TYPE_ANY 0x01    // Wildcard (p0f.fp sigs only)
#define WIN_TYPE_MOD 0x02    // Modulo check (p0f.fp sigs only)
#define WIN_TYPE_MSS 0x03    // Window size MSS multiplier
#define WIN_TYPE_MTU 0x04    // Window size MTU multiplier

// Record for a TCP signature read from p0f.fp:
struct tcp_sig_record {

	uint8_t generic  = 0;              // Generic entry?
	int32_t class_id = 0;              // OS class ID (-1 = user)
	int32_t name_id  = 0;              // OS name ID
	ext::optional<std::string> flavor; // Human-readable flavor string

	uint32_t label_id = 0; // Signature label ID

	std::vector<uint32_t> sys; // OS class / name IDs for user apps

	uint32_t line_no = 0; // Line number in p0f.fp

	uint8_t bad_ttl = 0; // TTL is generated randomly

	std::unique_ptr<struct tcp_sig> sig; // Actual signature data
};

#include "process.h"

struct packet_data;
struct packet_flow;

void tcp_register_sig(bool to_srv, uint8_t generic, int32_t sig_class, int32_t sig_name, const ext::optional<std::string> &sig_flavor, int32_t label_id, const std::vector<uint32_t> &sys, string_view value, uint32_t line_no);
std::unique_ptr<tcp_sig> fingerprint_tcp(bool to_srv, struct packet_data *pk, struct packet_flow *f, libp0f_context_t *libp0f_context);
void check_ts_tcp(bool to_srv, struct packet_data *pk, struct packet_flow *f, libp0f_context_t *libp0f_context);

#endif
