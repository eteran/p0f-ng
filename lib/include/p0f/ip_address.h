
#ifndef P0F_IP_ADDRESS_H_
#define P0F_IP_ADDRESS_H_

#include <netinet/in.h>

struct ip_address {
	union {
		in_addr ipv4;
		in6_addr ipv6;
	};
};

#endif
