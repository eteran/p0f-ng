/*
   p0f - portable IP and TCP headers
   ---------------------------------

   Note that all multi-byte fields are in network (i.e., big) endian, and may
   need to be converted before use.

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef P0F_TCP_H_
#define P0F_TCP_H_

#include <cstdint>

/* -----------
 * IP common *
 * ----------*/

// Protocol versions:
enum IP_VER {
	IP_VER4 = 0x04,
	IP_VER6 = 0x06,
};

// IP-level ECN:
enum : uint8_t {
	IP_TOS_CE  = 0x01, // Congestion encountered
	IP_TOS_ECT = 0x02, // ECN supported
};

// Encapsulated protocols we care about:
enum {
	PROTO_TCP = 0x06,
};

/*-------
 * IPv4 *
 * -----*/
struct ipv4_hdr {
	uint8_t ver_hlen;   // IP version (4), IP hdr len in dwords (4)
	uint8_t tos_ecn;    // ToS field (6), ECN flags (2)
	uint16_t tot_len;   // Total packet length, in bytes
	uint16_t id;        // IP ID
	uint16_t flags_off; // Flags (3), fragment offset (13)
	uint8_t ttl;        // Time to live
	uint8_t proto;      // Next protocol
	uint16_t cksum;     // Header checksum
	uint8_t src[4];     // Source IP
	uint8_t dst[4];     // Destination IP

	// Dword-aligned options may follow.
} __attribute__((packed));

// IP flags:
enum : uint16_t {
	IP4_MBZ = 0x8000, // "Must be zero"
	IP4_DF  = 0x4000, // Don't fragment (usually PMTUD)
	IP4_MF  = 0x2000, // More fragments coming
};

/********
 * IPv6 *
 ********/
struct ipv6_hdr {
	uint32_t ver_tos; // Version (4), ToS (6), ECN (2), flow (20)
	uint16_t pay_len; // Total payload length, in bytes
	uint8_t proto;    // Next protocol
	uint8_t ttl;      // Time to live
	uint8_t src[16];  // Source IP
	uint8_t dst[16];  // Destination IP

	/* Dword-aligned options may follow if proto != PROTO_TCP and are
	 included in total_length; but we won't be seeing such traffic due
	 to BPF rules. */

} __attribute__((packed));

/*------
 * TCP *
 * ----*/
struct tcp_hdr {
	uint16_t sport;    // Source port
	uint16_t dport;    // Destination port
	uint32_t seq;      // Sequence number
	uint32_t ack;      // Acknowledgment number
	uint8_t doff_rsvd; // Data off dwords (4), rsvd (3), ECN (1)
	uint8_t flags;     // Flags, including ECN
	uint16_t win;      // Window size
	uint16_t cksum;    // Header and payload checksum
	uint16_t urg;      // "Urgent" pointer

	// Dword-aligned options may follow.
} __attribute__((packed));

// Normal flags:
enum : uint8_t {
	TCP_FIN  = 0x01,
	TCP_SYN  = 0x02,
	TCP_RST  = 0x04,
	TCP_PUSH = 0x08,
	TCP_ACK  = 0x10,
	TCP_URG  = 0x20,
};

// ECN stuff:
enum : uint8_t {
	TCP_ECE    = 0x40, // ECN supported (SYN) or detected
	TCP_CWR    = 0x80, // ECE acknowledgment
	TCP_NS_RES = 0x01, // ECE notification via TCP
};

// Notable options:
enum {
	TCPOPT_EOL    = 0, // End of options (1)
	TCPOPT_NOP    = 1, // No-op (1)
	TCPOPT_MAXSEG = 2, // Maximum segment size (4)
	TCPOPT_WSCALE = 3, // Window scaling (3)
	TCPOPT_SACKOK = 4, // Selective ACK permitted (2)
	TCPOPT_SACK   = 5, // Actual selective ACK (10-34)
	TCPOPT_TSTAMP = 8, // Timestamp (10)
};

/* -------------
 * Other stuff *
 * ------------*/
constexpr int MIN_TCP4 = (sizeof(ipv4_hdr) + sizeof(tcp_hdr));
constexpr int MIN_TCP6 = (sizeof(ipv6_hdr) + sizeof(tcp_hdr));

#endif
