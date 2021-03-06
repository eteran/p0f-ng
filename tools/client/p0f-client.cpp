/*
   p0f-client - simple API client
   ------------------------------

   Can be used to query p0f API sockets.

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include "p0f/api.h"
#include "p0f/debug.h"

namespace {

/* Parse IPv4 address into a buffer. */
void parse_addr4(const char *str, in_addr *ret) {

	uint32_t a1;
	uint32_t a2;
	uint32_t a3;
	uint32_t a4;
	uint8_t buffer[sizeof(in_addr)];

	if (sscanf(str, "%u.%u.%u.%u", &a1, &a2, &a3, &a4) != 4) {
		FATAL("Malformed IPv4 address.");
	}

	if (a1 > 255 || a2 > 255 || a3 > 255 || a4 > 255) {
		FATAL("Malformed IPv4 address.");
	}

	buffer[0] = static_cast<uint8_t>(a1);
	buffer[1] = static_cast<uint8_t>(a2);
	buffer[2] = static_cast<uint8_t>(a3);
	buffer[3] = static_cast<uint8_t>(a4);

	memcpy(ret, buffer, sizeof(in_addr));
}

/* Parse IPv6 address into a buffer. */
void parse_addr6(const char *str, in6_addr *ret) {

	uint32_t seg = 0;
	uint32_t val;

	uint8_t buffer[sizeof(in6_addr)];

	while (*str) {
		if (seg == 8) {
			FATAL("Malformed IPv6 address (too many segments).");
		}

		if (sscanf(str, "%x", &val) != 1 || val > 65535) {
			FATAL("Malformed IPv6 address (bad octet value).");
		}

		buffer[seg * 2]     = val >> 8;
		buffer[seg * 2 + 1] = val;

		seg++;

		while (isxdigit(*str)) {
			str++;
		}

		if (*str) {
			str++;
		}
	}

	if (seg != 8) {
		FATAL("Malformed IPv6 address (don't abbreviate).");
	}

	memcpy(ret, buffer, sizeof(in6_addr));
}

}

int main(int argc, char **argv) {

	if (argc != 3) {
		ERRORF("Usage: p0f-client /path/to/socket host_ip\n");
		exit(1);
	}

	p0f_api_query q;
	q.magic = P0F_QUERY_MAGIC;

	if (strchr(argv[2], ':')) {
		parse_addr6(argv[2], &q.addr.ipv6);
		q.addr_type = P0F_ADDR_IPV6;
	} else {
		parse_addr4(argv[2], &q.addr.ipv4);
		q.addr_type = P0F_ADDR_IPV4;
	}

	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		PFATAL("Call to socket() failed.");
	}

	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;

	if (strlen(argv[1]) >= sizeof(sun.sun_path)) {
		FATAL("API socket filename is too long for sockaddr_un (blame Unix).");
	}

	strcpy(sun.sun_path, argv[1]);

	if (connect(sock, reinterpret_cast<struct sockaddr *>(&sun), sizeof(sun))) {
		PFATAL("Can't connect to API socket.");
	}

	if (write(sock, &q, sizeof(p0f_api_query)) != sizeof(p0f_api_query)) {
		FATAL("Short write to API socket.");
	}

	p0f_api_response r;
	if (read(sock, &r, sizeof(p0f_api_response)) != sizeof(p0f_api_response)) {
		FATAL("Short read from API socket.");
	}

	close(sock);

	if (r.magic != P0F_RESP_MAGIC) {
		FATAL("Bad response magic (0x%08x).\n", r.magic);
	}

	if (r.status == P0F_STATUS_BADQUERY) {
		FATAL("P0f did not understand the query.\n");
	}

	if (r.status == P0F_STATUS_NOMATCH) {
		SAYF("No matching host in p0f cache. That's all we know.\n");
		return 0;
	}

	time_t ut    = r.first_seen;
	struct tm *t = localtime(&ut);
	char tmp[128];
	strftime(tmp, sizeof(tmp), "%Y/%m/%d %H:%M:%S", t);

	SAYF("First seen    = %s\n", tmp);

	ut = r.last_seen;
	t  = localtime(&ut);
	strftime(tmp, sizeof(tmp), "%Y/%m/%d %H:%M:%S", t);

	SAYF("Last update   = %s\n", tmp);

	SAYF("Total flows   = %u\n", r.total_conn);

	if (!r.os_name[0]) {
		SAYF("Detected OS   = ???\n");
	} else {
		SAYF("Detected OS   = %s %s%s%s\n", r.os_name, r.os_flavor,
			 (r.os_match_q & P0F_MATCH_GENERIC) ? " [generic]" : "",
			 (r.os_match_q & P0F_MATCH_FUZZY) ? " [fuzzy]" : "");
	}

	if (!r.http_name[0]) {
		SAYF("HTTP software = ???\n");
	} else {
		SAYF("HTTP software = %s %s (ID %s)\n", r.http_name, r.http_flavor,
			 (r.bad_sw == 2) ? "is fake" : (r.bad_sw ? "OS mismatch" : "seems legit"));
	}

	if (!r.link_type[0]) {
		SAYF("Network link  = ???\n");
	} else {
		SAYF("Network link  = %s\n", r.link_type);
	}

	if (!r.language[0]) {
		SAYF("Language      = ???\n");
	} else {
		SAYF("Language      = %s\n", r.language);
	}

	if (r.distance == -1) {
		SAYF("Distance      = ???\n");
	} else {
		SAYF("Distance      = %u\n", r.distance);
	}

	if (r.last_nat) {
		ut = r.last_nat;
		t  = localtime(&ut);
		strftime(tmp, 128, "%Y/%m/%d %H:%M:%S", t);
		SAYF("IP sharing    = %s\n", tmp);
	}

	if (r.last_chg) {
		ut = r.last_chg;
		t  = localtime(&ut);
		strftime(tmp, 128, "%Y/%m/%d %H:%M:%S", t);
		SAYF("Sys change    = %s\n", tmp);
	}

	if (r.uptime_min) {
		SAYF("Uptime        = %u days %u hrs %u min (modulo %u days)\n",
			 r.uptime_min / 60 / 24, (r.uptime_min / 60) % 24, r.uptime_min % 60,
			 r.up_mod_days);
	}
}
