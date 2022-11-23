/*
   p0f - packet capture and overall host / flow bookkeeping
   --------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef P0F_PROCESS_H_
#define P0F_PROCESS_H_

#include <string>
#include <vector>

#include "fp_http.h"
#include "fp_tcp.h"
#include "ip_address.h"

struct tcp_sig;
struct libp0f;

// Parsed information handed over by the pcap callback:
struct packet_data {

	uint8_t ip_ver   = 0; // IP_VER4, IP_VER6
	uint8_t tcp_type = 0; // TCP_SYN, ACK, FIN, RST

	ip_address src = {}; // Source address (left-aligned)
	ip_address dst = {}; // Destination address (left-aligned

	uint16_t sport = 0; // Source port
	uint16_t dport = 0; // Destination port

	uint8_t ttl = 0; // Observed TTL
	uint8_t tos = 0; // IP ToS value

	uint16_t mss     = 0; // Maximum segment size
	uint16_t win     = 0; // Window size
	uint8_t wscale   = 0; // Window scaling
	uint16_t tot_hdr = 0; // Total headers (for MTU calc)

	std::vector<uint8_t> opt_layout; // Ordering of TCP options
	uint8_t opt_eol_pad = 0;         // Amount of padding past EOL

	uint32_t ts1 = 0; // Own timestamp

	uint32_t quirks = 0; // QUIRK_*

	uint8_t ip_opt_len = 0; // Length of IP options

	const uint8_t *payload = nullptr; // TCP payload
	size_t pay_len         = 0;       // Length of TCP payload

	uint32_t seq = 0; // seq value seen
};

// IP-level quirks:
enum Quirks : uint32_t {
	QUIRK_ECN     = 0x00000001, // ECN supported
	QUIRK_DF      = 0x00000002, // DF used (probably PMTUD)
	QUIRK_NZ_ID   = 0x00000004, // Non-zero IDs when DF set
	QUIRK_ZERO_ID = 0x00000008, // Zero IDs when DF not set
	QUIRK_NZ_MBZ  = 0x00000010, // IP "must be zero" field isn't
	QUIRK_FLOW    = 0x00000020, // IPv6 flows used

	// Core TCP quirks:
	QUIRK_ZERO_SEQ = 0x00001000, // SEQ is zero
	QUIRK_NZ_ACK   = 0x00002000, // ACK non-zero when ACK flag not set
	QUIRK_ZERO_ACK = 0x00004000, // ACK is zero when ACK flag set
	QUIRK_NZ_URG   = 0x00008000, // URG non-zero when URG flag not set
	QUIRK_URG      = 0x00010000, // URG flag set
	QUIRK_PUSH     = 0x00020000, // PUSH flag on a control packet

	// TCP option quirks:
	QUIRK_OPT_ZERO_TS1 = 0x01000000, // Own timestamp set to zero
	QUIRK_OPT_NZ_TS2   = 0x02000000, // Peer timestamp non-zero on SYN
	QUIRK_OPT_EOL_NZ   = 0x04000000, // Non-zero padding past EOL
	QUIRK_OPT_EXWS     = 0x08000000, // Excessive window scaling
	QUIRK_OPT_BAD      = 0x10000000, // Problem parsing TCP options
};

// Host record with persistent fingerprinting data:
struct host_data {

	host_data *prev  = nullptr;
	host_data *next  = nullptr; // Linked lists
	host_data *older = nullptr;
	host_data *newer = nullptr;
	uint32_t use_cnt = 0; // Number of packet_flows attached

	time_t first_seen   = 0; // Record created (unix time)
	time_t last_seen    = 0; // Host last seen (unix time)
	uint32_t total_conn = 0; // Total number of connections ever

	uint8_t ip_ver  = 0;  // Address type
	ip_address addr = {}; // Host address data

	std::unique_ptr<tcp_sig> last_syn;    // Sig of the most recent SYN
	std::unique_ptr<tcp_sig> last_synack; // Sig of the most recent SYN+ACK

	uint32_t last_class_id = 0;             // OS class ID (-1 = not found)
	uint32_t last_name_id  = 0;             // OS name ID (-1 = not found)
	std::optional<std::string> last_flavor; // Last OS flavor

	uint8_t last_quality = 0; // Generic or fuzzy match?

	std::optional<std::string> link_type; // MTU-derived link type

	uint8_t cli_scores[NAT_SCORES] = {}; // Scoreboard for client NAT
	uint8_t srv_scores[NAT_SCORES] = {}; // Scoreboard for server NAT
	uint16_t nat_reasons           = 0;  // NAT complaints

	time_t last_nat = 0; // Last NAT detection time
	time_t last_chg = 0; // Last OS change detection time

	uint16_t last_port = 0; // Source port on last SYN

	uint8_t distance = 0; // Last measured distance

	int32_t last_up_min  = 0; // Last computed uptime (-1 = none)
	uint32_t up_mod_days = 0; // Uptime modulo (days)

	// HTTP business:
	std::shared_ptr<http_sig> http_req_os; // Last request, if class != -1
	std::shared_ptr<http_sig> http_resp;   // Last response

	uint32_t http_name_id = 0;              // Client name ID (-1 = not found)
	std::optional<std::string> http_flavor; // Client flavor

	const char *language = nullptr; // Detected language

	uint8_t bad_sw = 0; // Used dishonest U-A or Server?

	uint16_t http_resp_port = 0; // Port on which response seen
};

// Reasons for NAT detection:
enum Reasons : uint16_t {
	NAT_APP_SIG  = 0x0001, // App signature <-> OS mismatch
	NAT_OS_SIG   = 0x0002, // OS detection mismatch
	NAT_UNK_DIFF = 0x0004, // Current sig unknown, but different
	NAT_TO_UNK   = 0x0008, // Sig changed from known to unknown
	NAT_TS       = 0x0010, // Timestamp goes back
	NAT_PORT     = 0x0020, // Source port goes back
	NAT_TTL      = 0x0040, // TTL changes unexpectedly
	NAT_FUZZY    = 0x0080, // Signature fuzziness changes
	NAT_MSS      = 0x0100, // MSS changes
	NAT_APP_LB   = 0x0200, // Server signature changes
	NAT_APP_VIA  = 0x0400, // Via / X-Forwarded-For seen
	NAT_APP_DATE = 0x0800, // Date changes in a weird way
	NAT_APP_UA   = 0x1000, // User-Agent OS inconsistency
};

// TCP flow record, maintained until all fingerprinting modules are happy:
struct packet_flow {
	packet_flow *prev  = nullptr;
	packet_flow *next  = nullptr; // Linked lists
	packet_flow *older = nullptr;
	packet_flow *newer = nullptr;
	uint32_t bucket    = 0; // Bucket this flow belongs to

	host_data *client = nullptr; // Requesting client
	host_data *server = nullptr; // Target server

	uint16_t cli_port = 0; // Client port
	uint16_t srv_port = 0; // Server port

	bool acked   = false; // SYN+ACK received?
	bool sendsyn = false; // Created by p0f-sendsyn?

	int16_t srv_tps = 0; // Computed TS divisor (-1 = bad)
	int16_t cli_tps = 0;

	std::string request;       // Client-originating data
	uint32_t next_cli_seq = 0; // Next seq on cli -> srv packet

	std::string response;      // Server-originating data
	uint32_t next_srv_seq = 0; // Next seq on srv -> cli packet
	uint16_t syn_mss      = 0; // MSS on SYN packet

	time_t created = 0; // Flow creation date (unix time)

	// Application-level fingerprinting:

	int8_t in_http = 0; // 0 = tbd, 1 = yes, -1 = no

	bool http_req_done = false; // Done collecting req headers?
	uint32_t http_pos  = 0;     // Current parsing offset
	bool http_gotresp1 = false; // Got initial line of a response?

	http_sig http_tmp = {}; // Temporary signature
};

struct process_context_t {
	process_context_t(libp0f *ctx)
		: ctx_(ctx) {}

public:
	void parse_packet_frame(timeval ts, const uint8_t *data, size_t packet_len);
	uint64_t get_unix_time_ms();
	time_t get_unix_time();
	void add_nat_score(bool to_srv, const packet_flow *f, uint16_t reason, uint8_t score);
	void verify_tool_class(bool to_srv, const packet_flow *f, const std::vector<uint32_t> &sys);
	host_data *lookup_host(const ip_address &addr, uint8_t ip_ver);
	void destroy_all_hosts();

private:
	packet_flow *lookup_flow(packet_data *pk, bool *to_srv);
	void destroy_flow(packet_flow *f);
	void touch_host(host_data *h);
	void nuke_flows(bool silent);
	void destroy_host(host_data *h);
	void nuke_hosts();
	host_data *create_host(const ip_address &addr, uint8_t ip_ver);
	void flow_dispatch(packet_data *pk);
	packet_flow *create_flow_from_syn(packet_data *pk);
	void expire_cache();

private:
	host_data *host_by_age_ = nullptr; // All host entries, by last mod
	host_data *newest_host_ = nullptr; // Tail of the list

	packet_flow *flow_by_age_ = nullptr; // All flows, by creation time
	packet_flow *newest_flow_ = nullptr; // Tail of the list

	struct timeval cur_time_ = {}; // Current time, courtesy of pcap

	// Bucketed hosts and flows:
	host_data *host_b_[HOST_BUCKETS]   = {};
	packet_flow *flow_b_[FLOW_BUCKETS] = {};

	// Counters for bookkeeping purposes
	uint32_t host_cnt_ = 0;
	uint32_t flow_cnt_ = 0;

	uint8_t bad_packets_ = 0; // Seen non-IP packets?

private:
	libp0f *ctx_ = nullptr;
};

#endif
