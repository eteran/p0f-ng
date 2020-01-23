/*
   p0f-sendsyn - SYN sender
   ------------------------

   This trivial utility sends 8 SYN packets to open ports on destination hosts,
   and lets you capture SYN+ACK signatures. The problem with SYN+ACK
   fingerprinting is that on some systems, the response varies depending on the
   use of window scaling, timestamps, or selective ACK in the initial SYN - so
   this utility is necessary to exercise all the code paths.

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "p0f/debug.h"
#include "p0f/tcp.h"

namespace {

/* Do a basic IPv4 TCP checksum. */
void tcp_cksum(uint8_t *src, uint8_t *dst, tcp_hdr *t, uint8_t opt_len) {

	if (opt_len % 4) {
		FATAL("Packet size not aligned to 4.");
	}

	t->cksum = 0;

	uint32_t sum = PROTO_TCP + sizeof(tcp_hdr) + opt_len;

	auto p = reinterpret_cast<uint8_t *>(t);

	for (uint32_t i = 0; i < sizeof(tcp_hdr) + opt_len; i += 2, p += 2) {
		sum += (*p << 8) + p[1];
	}

	p = src;

	for (uint32_t i = 0; i < 4; i += 2, p += 2) {
		sum += (*p << 8) + p[1];
	}

	p = dst;

	for (uint32_t i = 0; i < 4; i += 2, p += 2) {
		sum += (*p << 8) + p[1];
	}

	t->cksum = htons(~(sum + (sum >> 16)));
}

/* Parse IPv4 address into a buffer. */
void parse_addr(char *str, uint8_t *ret) {

	uint32_t a1, a2, a3, a4;

	if (sscanf(str, "%u.%u.%u.%u", &a1, &a2, &a3, &a4) != 4) {
		FATAL("Malformed IPv4 address.");
	}

	if (a1 > 255 || a2 > 255 || a3 > 255 || a4 > 255) {
		FATAL("Malformed IPv4 address.");
	}

	ret[0] = a1;
	ret[1] = a2;
	ret[2] = a3;
	ret[3] = a4;
}

#define W(_x) (_x) >> 8, (_x)&0xff
#define D(_x) (_x) >> 24, ((_x) >> 16) & 0xff, ((_x) >> 8) & 0xff, (_x)&0xff

#define EOL TCPOPT_EOL
#define NOP TCPOPT_NOP
#define MSS(_x) TCPOPT_MAXSEG, 4, W(_x)
#define WS(_x) TCPOPT_WSCALE, 3, (_x)
#define SOK TCPOPT_SACKOK, 2
#define TS(_x, _y) TCPOPT_TSTAMP, 10, D(_x), D(_y)

/* There are virtually no OSes that do not send MSS. Support for RFC 1323
 * and 2018 is not given, so we have to test various combinations here. */
const uint8_t opt_combos[8][24] = {

	{MSS(SPECIAL_MSS), NOP, EOL}, /* 6  */

	{MSS(SPECIAL_MSS), SOK, NOP, EOL}, /* 8  */

	{MSS(SPECIAL_MSS), WS(5), NOP, EOL}, /* 9  */

	{MSS(SPECIAL_MSS), WS(5), SOK, NOP, EOL}, /* 12 */

	{MSS(SPECIAL_MSS), TS(1337, 0), NOP, EOL}, /* 17 */

	{MSS(SPECIAL_MSS), SOK, TS(1337, 0), NOP, EOL}, /* 19 */

	{MSS(SPECIAL_MSS), WS(5), TS(1337, 0), NOP, EOL}, /* 20 */

	{MSS(SPECIAL_MSS), WS(5), SOK, TS(1337, 0), NOP, EOL} /* 22 */

};

}

int main(int argc, char **argv) {

	uint8_t work_buf[MIN_TCP4 + 24];

	auto ip4      = reinterpret_cast<struct ipv4_hdr *>(work_buf);
	auto tcp      = reinterpret_cast<tcp_hdr *>(ip4 + 1);
	uint8_t *opts = work_buf + MIN_TCP4;

	if (argc != 4) {
		ERRORF("Usage: p0f-sendsyn your_ip dst_ip port\n");
		exit(1);
	}

	parse_addr(argv[1], ip4->src);
	parse_addr(argv[2], ip4->dst);

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		PFATAL("Can't open raw socket (you need to be root).");
	}

	const char one = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(char))) {
		PFATAL("setsockopt() on raw socket failed.");
	}

	struct sockaddr_in sin;
	sin.sin_family = PF_INET;

	memcpy(&sin.sin_addr.s_addr, ip4->dst, 4);

	ip4->ver_hlen = 0x45;
	ip4->tot_len  = htons(MIN_TCP4 + 24);
	ip4->ttl      = 192;
	ip4->proto    = PROTO_TCP;

	tcp->dport     = htons(atoi(argv[3]));
	tcp->seq       = htonl(0x12345678);
	tcp->doff_rsvd = ((sizeof(tcp_hdr) + 24) / 4) << 4;
	tcp->flags     = TCP_SYN;
	tcp->win       = htons(SPECIAL_WIN);

	for (uint32_t i = 0; i < 8; ++i) {

		tcp->sport = htons(65535 - i);

		memcpy(opts, opt_combos[i], 24);
		tcp_cksum(ip4->src, ip4->dst, tcp, 24);

		if (sendto(sock, work_buf, sizeof(work_buf), 0, reinterpret_cast<struct sockaddr *>(&sin), sizeof(struct sockaddr_in)) < 0) {
			PFATAL("sendto() fails.");
		}

		usleep(100000);
	}

	SAYF("Eight packets sent! Check p0f output to examine responses, if any.\n");
}
