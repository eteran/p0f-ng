/*
   p0f - packet capture and overall host / flow bookkeeping
   --------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "p0f/config.h"
#include "p0f/debug.h"
#include "p0f/fp_http.h"
#include "p0f/fp_mtu.h"
#include "p0f/fp_tcp.h"
#include "p0f/hash.h"
#include "p0f/libp0f.h"
#include "p0f/process.h"
#include "p0f/readfp.h"
#include "p0f/tcp.h"
#include "p0f/util.h"

namespace {

/* Calculate hash bucket for packet_flow. Keep the hash symmetrical: switching
 * source and dest should have no effect. */
uint32_t get_flow_bucket(packet_data *pk) {

	uint32_t bucket;

	if (pk->ip_ver == IP_VER4) {
		bucket = hash32(pk->src, 4) ^ hash32(pk->dst, 4);
	} else {
		bucket = hash32(pk->src, 16) ^ hash32(pk->dst, 16);
	}

	bucket ^= hash32(&pk->sport, 2) ^ hash32(&pk->dport, 2);

	return bucket % FLOW_BUCKETS;
}

// Calculate hash bucket for host_data.
uint32_t get_host_bucket(const uint8_t *addr, uint8_t ip_ver) {
	uint32_t bucket = hash32(addr, (ip_ver == IP_VER4) ? 4 : 16);
	return bucket % HOST_BUCKETS;
}

bool compare_ips(uint8_t lhs[16], uint8_t rhs[16], uint8_t ip_ver) {
	return memcmp(lhs, rhs, (ip_ver == IP_VER4) ? 4 : 16) == 0;
}

}

// Look up an existing flow.
packet_flow *process_context_t::lookup_flow(packet_data *pk, bool *to_srv) {

	uint32_t bucket = get_flow_bucket(pk);

	for (packet_flow *f = flow_b_[bucket]; f; f = f->next) {

		if (pk->ip_ver != f->client->ip_ver) {
			continue;
		}

		if (pk->sport == f->cli_port && pk->dport == f->srv_port && compare_ips(pk->src, f->client->addr, pk->ip_ver) && compare_ips(pk->dst, f->server->addr, pk->ip_ver)) {
			*to_srv = true;
			return f;
		}

		if (pk->dport == f->cli_port && pk->sport == f->srv_port && compare_ips(pk->dst, f->client->addr, pk->ip_ver) && compare_ips(pk->src, f->server->addr, pk->ip_ver)) {
			*to_srv = false;
			return f;
		}
	}

	return nullptr;
}

// Destroy a flow.
void process_context_t::destroy_flow(packet_flow *f) {

	DEBUG("[#] Destroying flow: %s/%u -> ",
		  addr_to_str(f->client->addr, f->client->ip_ver),
		  f->cli_port);

	DEBUG("%s/%u (bucket %u)\n",
		  addr_to_str(f->server->addr, f->server->ip_ver),
		  f->srv_port,
		  f->bucket);

	// Remove it from the bucketed linked list.
	if (f->next) {
		f->next->prev = f->prev;
	}

	if (f->prev) {
		f->prev->next = f->next;
	} else {
		flow_b_[f->bucket] = f->next;
	}

	// Remove from the by-age linked list.
	if (f->newer) {
		f->newer->older = f->older;
	} else {
		newest_flow_ = f->older;
	}

	if (f->older) {
		f->older->newer = f->newer;
	} else {
		flow_by_age_ = f->newer;
	}

	// Free memory, etc.
	f->client->use_cnt--;
	f->server->use_cnt--;

	delete f;

	flow_cnt_--;
}

// Touch host data to make it more recent.
void process_context_t::touch_host(host_data *h) {

	DEBUG("[#] Refreshing host data: %s\n", addr_to_str(h->addr, h->ip_ver));

	if (h != newest_host_) {

		// Remove from the the by-age linked list.
		h->newer->older = h->older;

		if (h->older) {
			h->older->newer = h->newer;
		} else {
			host_by_age_ = h->newer;
		}

		// Re-insert in front.
		newest_host_->newer = h;
		h->older            = newest_host_;
		h->newer            = nullptr;

		newest_host_ = h;

		/* This wasn't the only entry on the list, so there is no
		 * need to update the tail (host_by_age). */
	}

	// Update last seen time.
	h->last_seen = get_unix_time();
}

// Indiscriminately kill some of the oldest flows.
void process_context_t::nuke_flows(bool silent) {

	uint32_t kcnt = 1 + (flow_cnt_ * KILL_PERCENT / 100);

	if (silent) {
		DEBUG("[#] Pruning connections - trying to delete %u...\n", kcnt);
	} else {
		ctx_->alert(Alert::TooManyConnections, kcnt);
	}

	while (kcnt-- && flow_by_age_) {
		destroy_flow(flow_by_age_);
	}
}

// Destroy host data.
void process_context_t::destroy_host(host_data *h) {

	const uint32_t bucket = get_host_bucket(h->addr, h->ip_ver);

	if (h->use_cnt) {
		FATAL("Attempt to destroy used host data.");
	}

	DEBUG("[#] Destroying host data: %s (bucket %d)\n",
		  addr_to_str(h->addr, h->ip_ver), bucket);

	// Remove it from the bucketed linked list.
	if (h->next) {
		h->next->prev = h->prev;
	}

	if (h->prev) {
		h->prev->next = h->next;
	} else {
		host_b_[bucket] = h->next;
	}

	// Remove from the by-age linked list.
	if (h->newer) {
		h->newer->older = h->older;
	} else {
		newest_host_ = h->older;
	}

	if (h->older) {
		h->older->newer = h->newer;
	} else {
		host_by_age_ = h->newer;
	}

	delete h;

	host_cnt_--;
}

// Indiscriminately kill some of the older hosts.
void process_context_t::nuke_hosts() {

	uint32_t kcnt     = 1 + (host_cnt_ * KILL_PERCENT / 100);
	host_data *target = host_by_age_;

	ctx_->alert(Alert::TooManyHosts, kcnt);

	nuke_flows(true);

	while (kcnt && target) {
		host_data *next = target->older;
		if (!target->use_cnt) {
			kcnt--;
			destroy_host(target);
		}
		target = next;
	}
}

// Create a minimal host data.
host_data *process_context_t::create_host(uint8_t *addr, uint8_t ip_ver) {

	uint32_t bucket = get_host_bucket(addr, ip_ver);

	if (host_cnt_ > ctx_->max_hosts) {
		nuke_hosts();
	}

	DEBUG("[#] Creating host data: %s (bucket %u)\n",
		  addr_to_str(addr, ip_ver), bucket);

	auto nh = new host_data;

	// Insert into the bucketed linked list.
	if (host_b_[bucket]) {
		host_b_[bucket]->prev = nh;
		nh->next              = host_b_[bucket];
	}

	host_b_[bucket] = nh;

	// Insert into the by-age linked list.
	if (newest_host_) {
		newest_host_->newer = nh;
		nh->older           = newest_host_;
	} else {
		host_by_age_ = nh;
	}

	newest_host_ = nh;

	// Populate other data.
	nh->ip_ver = ip_ver;
	memcpy(nh->addr, addr, (ip_ver == IP_VER4) ? 4 : 16);

	nh->last_seen = nh->first_seen = get_unix_time();

	nh->last_up_min   = -1;
	nh->last_class_id = InvalidId;
	nh->last_name_id  = InvalidId;
	nh->http_name_id  = InvalidId;
	nh->distance      = -1;

	host_cnt_++;

	return nh;
}

// Create flow, and host data if necessary. If counts exceeded, prune old.
packet_flow *process_context_t::create_flow_from_syn(packet_data *pk) {

	uint32_t bucket = get_flow_bucket(pk);

	if (flow_cnt_ > ctx_->max_conn) {
		nuke_flows(false);
	}

	DEBUG("[#] Creating flow from SYN: %s/%u -> ",
		  addr_to_str(pk->src, pk->ip_ver), pk->sport);

	DEBUG("%s/%u (bucket %u)\n",
		  addr_to_str(pk->dst, pk->ip_ver), pk->dport, bucket);

	auto nf = new packet_flow;

	nf->client = lookup_host(pk->src, pk->ip_ver);

	if (nf->client) {
		touch_host(nf->client);
	} else {
		nf->client = create_host(pk->src, pk->ip_ver);
	}

	nf->server = lookup_host(pk->dst, pk->ip_ver);

	if (nf->server) {
		touch_host(nf->server);
	} else {
		nf->server = create_host(pk->dst, pk->ip_ver);
	}

	nf->client->use_cnt++;
	nf->server->use_cnt++;

	nf->client->total_conn++;
	nf->server->total_conn++;

	// Insert into the bucketed linked list.
	if (flow_b_[bucket]) {
		flow_b_[bucket]->prev = nf;
		nf->next              = flow_b_[bucket];
	}

	flow_b_[bucket] = nf;

	// Insert into the by-age linked list
	if (newest_flow_) {
		newest_flow_->newer = nf;
		nf->older           = newest_flow_;
	} else {
		flow_by_age_ = nf;
	}

	newest_flow_ = nf;

	// Populate other data
	nf->cli_port = pk->sport;
	nf->srv_port = pk->dport;
	nf->bucket   = bucket;
	nf->created  = get_unix_time();

	nf->next_cli_seq = pk->seq + 1;

	flow_cnt_++;
	return nf;
}

// Insert data from a packet into a flow, call handlers as appropriate.
void process_context_t::flow_dispatch(packet_data *pk) {

	std::unique_ptr<tcp_sig> tsig;
	bool to_srv       = false;
	uint8_t need_more = 0;

	DEBUG("[#] Received TCP packet: %s/%u -> ",
		  addr_to_str(pk->src, pk->ip_ver),
		  pk->sport);

	DEBUG("%s/%u (type 0x%02x, pay_len = %lu)\n",
		  addr_to_str(pk->dst, pk->ip_ver),
		  pk->dport,
		  pk->tcp_type,
		  pk->pay_len);

	packet_flow *f = lookup_flow(pk, &to_srv);

	switch (pk->tcp_type) {
	case TCP_SYN:
		if (f) {
			// Perhaps just a simple dupe?
			if (to_srv && f->next_cli_seq - 1 == pk->seq) {
				return;
			}

			DEBUG("[#] New SYN for an existing flow, resetting.\n");
			destroy_flow(f);
		}

		f = create_flow_from_syn(pk);

		tsig = ctx_->tcp_context.fingerprint_tcp(1, pk, f);

		/* We don't want to do any further processing on generic non-OS
		 signatures (e.g. NMap). The easiest way to guarantee that is to
		 kill the flow. */

		if (!tsig && !f->sendsyn) {
			destroy_flow(f);
			return;
		}

		ctx_->mtu_context.fingerprint_mtu(1, pk, f);
		ctx_->tcp_context.check_ts_tcp(1, pk, f);

		if (tsig) {
			/* This can't be done in fingerprint_tcp because check_ts_tcp()
			 * depends on having original SYN / SYN+ACK data. */
			f->client->last_syn = std::move(tsig);
		}

		break;

	case TCP_SYN | TCP_ACK:
		if (!f) {
			DEBUG("[#] Stray SYN+ACK with no flow.\n");
			return;
		}

		// This is about as far as we want to go with p0f-sendsyn.
		if (f->sendsyn) {

			ctx_->tcp_context.fingerprint_tcp(0, pk, f);
			destroy_flow(f);
			return;
		}

		if (to_srv) {

			DEBUG("[#] SYN+ACK from client to server, trippy.\n");
			return;
		}

		if (f->acked) {

			if (f->next_srv_seq - 1 != pk->seq) {
				DEBUG("[#] Repeated but non-identical SYN+ACK (0x%08x != 0x%08x).\n",
					  f->next_srv_seq - 1, pk->seq);
			}

			return;
		}

		f->acked = true;

		tsig = ctx_->tcp_context.fingerprint_tcp(0, pk, f);

		// SYN from real OS, SYN+ACK from a client stack. Weird, but whatever.
		if (!tsig) {
			destroy_flow(f);
			return;
		}

		ctx_->mtu_context.fingerprint_mtu(0, pk, f);
		ctx_->tcp_context.check_ts_tcp(0, pk, f);

		f->server->last_synack = std::move(tsig);
		f->next_srv_seq        = pk->seq + 1;
		break;

	case TCP_RST | TCP_ACK:
	case TCP_RST:
	case TCP_FIN | TCP_ACK:
	case TCP_FIN:
		if (f) {
			ctx_->tcp_context.check_ts_tcp(to_srv, pk, f);
			destroy_flow(f);
		}
		break;
	case TCP_ACK:
		if (!f) {
			return;
		}

		// Stop there, you criminal scum!
		if (f->sendsyn) {
			destroy_flow(f);
			return;
		}

		if (!f->acked) {
			DEBUG("[#] Never received SYN+ACK to complete handshake, huh.\n");
			destroy_flow(f);
			return;
		}

		if (to_srv) {

			/* We don't do stream reassembly, so if something arrives out of
			 * order, we won't catch it. Oh well. */
			if (f->next_cli_seq != pk->seq) {

				// Not a simple dupe?
				if (f->next_cli_seq - pk->pay_len != pk->seq) {
					DEBUG("[#] Expected client seq 0x%08x, got 0x%08x.\n", f->next_cli_seq, pk->seq);
				}

				return;
			}

			// Append data
			if (f->request.size() < MAX_FLOW_DATA && pk->pay_len) {
				const size_t read_amt = std::min<size_t>(pk->pay_len, MAX_FLOW_DATA - f->request.size());
				f->request.append(reinterpret_cast<const char *>(pk->payload), read_amt);
			}

			ctx_->tcp_context.check_ts_tcp(1, pk, f);

			f->next_cli_seq += pk->pay_len;

		} else {

			if (f->next_srv_seq != pk->seq) {

				// Not a simple dupe?
				if (f->next_srv_seq - pk->pay_len != pk->seq) {
					DEBUG("[#] Expected server seq 0x%08x, got 0x%08x.\n",
						  f->next_cli_seq, pk->seq);
				}

				return;
			}

			// Append data
			if (f->response.size() < MAX_FLOW_DATA && pk->pay_len) {
				const size_t read_amt = std::min<size_t>(pk->pay_len, MAX_FLOW_DATA - f->response.size());
				f->response.append(reinterpret_cast<const char *>(pk->payload), read_amt);
			}

			ctx_->tcp_context.check_ts_tcp(0, pk, f);

			f->next_srv_seq += pk->pay_len;
		}

		if (!pk->pay_len) {
			return;
		}

		need_more |= ctx_->http_context.process_http(to_srv, f);

		if (!need_more) {
			DEBUG("[#] All modules done, no need to keep tracking flow.\n");
			destroy_flow(f);
		} else if (f->request.size() >= MAX_FLOW_DATA && f->response.size() >= MAX_FLOW_DATA) {
			DEBUG("[#] Per-flow capture size limit exceeded.\n");
			destroy_flow(f);
		}
		break;
	default:
		WARN("Huh. Unexpected packet type 0x%02x in flow_dispatch().", pk->tcp_type);
	}
}

// Go through host and flow cache, expire outdated items.
void process_context_t::expire_cache() {

	static time_t pt;
	const time_t ct = get_unix_time();

	if (ct == pt) {
		return;
	}

	pt = ct;

	DEBUG("[#] Cache expiration kicks in...\n");

	while (flow_by_age_ && ct - flow_by_age_->created > ctx_->conn_max_age) {
		destroy_flow(flow_by_age_);
	}

	host_data *target = host_by_age_;

	while (target && ct - target->last_seen > ctx_->host_idle_limit * 60) {
		host_data *newer = target->newer;
		if (!target->use_cnt) {
			destroy_host(target);
		}
		target = newer;
	}
}

// Get unix time in milliseconds.
uint64_t process_context_t::get_unix_time_ms() {
	return (cur_time_.tv_sec) * 1000 + (cur_time_.tv_usec / 1000);
}

// Get unix time in seconds.
time_t process_context_t::get_unix_time() {
	return cur_time_.tv_sec;
}

void process_context_t::parse_packet_frame(struct timeval ts, const uint8_t *data, size_t packet_len) {

	cur_time_ = ts;

	ctx_->packet_cnt++;
	if (!(ctx_->packet_cnt % EXPIRE_INTERVAL)) {
		expire_cache();
	}

	packet_data pk = {};

	/* If there is no way we could have received a complete TCP packet,
	 * bail out early. */
	if (packet_len < MIN_TCP4) {
		DEBUG("[#] Packet too short for any IPv4 + TCP headers, giving up!\n");
		return;
	}

	pk.quirks = 0;

	const tcp_hdr *tcp = nullptr;

	if ((*data >> 4) == IP_VER4) {

		/* ----------------------
		 * IPv4 header parsing. *
		 * ---------------------*/
		auto ip4 = reinterpret_cast<const ipv4_hdr *>(data);

		uint32_t hdr_len   = (ip4->ver_hlen & 0x0F) * 4;
		uint16_t flags_off = ntohs(RD16(ip4->flags_off));
		uint16_t tot_len   = ntohs(RD16(ip4->tot_len));

		/* If the packet claims to be shorter than what we received off the wire,
		 * honor this claim to account for etherleak-type bugs. */
		if (packet_len > tot_len) {
			packet_len = tot_len;
			// DEBUG("[#] ipv4.tot_len = %u, adjusted accordingly.\n", tot_len);
		}

		// Bail out if the result leaves no room for IPv4 + TCP headers.
		if (packet_len < MIN_TCP4) {
			DEBUG("[#] packet_len = %lu. Too short for IPv4 + TCP, giving up!\n",
				  packet_len);
			return;
		}

		// Bail out if the declared length of IPv4 headers is nonsensical.
		if (hdr_len < sizeof(ipv4_hdr)) {
			DEBUG("[#] ipv4.hdr_len = %u. Too short for IPv4, giving up!\n",
				  hdr_len);
			return;
		}

		/* If the packet claims to be longer than the recv buffer, best to back
		 * off - even though we could just ignore this and recover. */
		if (tot_len > packet_len) {
			DEBUG("[#] ipv4.tot_len = %u but packet_len = %lu, bailing out!\n",
				  tot_len, packet_len);
			return;
		}

		/* And finally, bail out if after skipping the IPv4 header as specified
		 * (including options), there wouldn't be enough room for TCP. */
		if (hdr_len + sizeof(tcp_hdr) > packet_len) {
			DEBUG("[#] ipv4.hdr_len = %u, packet_len = %lu, no room for TCP!\n",
				  hdr_len, packet_len);
			return;
		}

		// Bail out if the subsequent protocol is not TCP.
		if (ip4->proto != PROTO_TCP) {
			DEBUG("[#] Whoa, IPv4 packet with non-TCP payload (%u)?\n", ip4->proto);
			return;
		}

		/* Ignore any traffic with MF or non-zero fragment offset specified. We
		 * can do enough just fingerprinting the non-fragmented traffic. */
		if (flags_off & ~(IP4_DF | IP4_MBZ)) {
			DEBUG("[#] Packet fragment (0x%04x), letting it slide!\n", flags_off);
			return;
		}

		// Store some relevant information about the packet.
		pk.ip_ver = IP_VER4;

		pk.ip_opt_len = hdr_len - 20;

		memcpy(pk.src, ip4->src, 4);
		memcpy(pk.dst, ip4->dst, 4);

		pk.tos = ip4->tos_ecn >> 2;

		pk.ttl = ip4->ttl;

		if (ip4->tos_ecn & (IP_TOS_CE | IP_TOS_ECT)) {
			pk.quirks |= QUIRK_ECN;
		}

		// Tag some of the corner cases associated with implementation quirks.
		if (flags_off & IP4_MBZ) {
			pk.quirks |= QUIRK_NZ_MBZ;
		}

		if (flags_off & IP4_DF) {

			pk.quirks |= QUIRK_DF;
			if (RD16(ip4->id)) {
				pk.quirks |= QUIRK_NZ_ID;
			}

		} else {

			if (!RD16(ip4->id)) {
				pk.quirks |= QUIRK_ZERO_ID;
			}
		}

		pk.tot_hdr = hdr_len;

		tcp = reinterpret_cast<const tcp_hdr *>(data + hdr_len);
		packet_len -= hdr_len;

	} else if ((*data >> 4) == IP_VER6) {

		/* ----------------------
		 * IPv6 header parsing. *
		 * ---------------------*/
		auto ip6         = reinterpret_cast<const ipv6_hdr *>(data);
		uint32_t ver_tos = ntohl(RD32(ip6->ver_tos));
		uint32_t tot_len = ntohs(RD16(ip6->pay_len)) + sizeof(ipv6_hdr);

		/* If the packet claims to be shorter than what we received off the wire,
		 * honor this claim to account for etherleak-type bugs. */
		if (packet_len > tot_len) {
			packet_len = tot_len;
			// DEBUG("[#] ipv6.tot_len = %u, adjusted accordingly.\n", tot_len);
		}

		// Bail out if the result leaves no room for IPv6 + TCP headers.
		if (packet_len < MIN_TCP6) {
			DEBUG("[#] packet_len = %lu. Too short for IPv6 + TCP, giving up!\n",
				  packet_len);
			return;
		}

		/* If the packet claims to be longer than the data we have, best to back
		 * off - even though we could just ignore this and recover. */
		if (tot_len > packet_len) {
			DEBUG("[#] ipv6.tot_len = %u but packet_len = %lu, bailing out!\n",
				  tot_len, packet_len);
			return;
		}

		/* Bail out if the subsequent protocol is not TCP. One day, we may try
		 * to parse and skip IPv6 extensions, but there seems to be no point in
		 * it today. */
		if (ip6->proto != PROTO_TCP) {
			DEBUG("[#] IPv6 packet with non-TCP payload (%u).\n", ip6->proto);
			return;
		}

		// Store some relevant information about the packet.
		pk.ip_ver = IP_VER6;

		pk.ip_opt_len = 0;

		memcpy(pk.src, ip6->src, 16);
		memcpy(pk.dst, ip6->dst, 16);

		pk.tos = (ver_tos >> 22) & 0x3F;

		pk.ttl = ip6->ttl;

		if (ver_tos & 0xFFFFF) {
			pk.quirks |= QUIRK_FLOW;
		}

		if ((ver_tos >> 20) & (IP_TOS_CE | IP_TOS_ECT)) {
			pk.quirks |= QUIRK_ECN;
		}

		pk.tot_hdr = sizeof(ipv6_hdr);

		tcp = reinterpret_cast<const tcp_hdr *>(ip6 + 1);
		packet_len -= sizeof(ipv6_hdr);

	} else {
		if (!bad_packets_) {
			WARN("Unknown packet type %u, link detection issue?", *data >> 4);
			bad_packets_ = 1;
		}

		return;
	}

	/* -------------
	 * TCP parsing *
	 * ------------*/
	data = reinterpret_cast<const uint8_t *>(tcp);

	uint32_t tcp_doff = (tcp->doff_rsvd >> 4) * 4;

	// As usual, let's start with sanity checks.
	if (tcp_doff < sizeof(tcp_hdr)) {
		DEBUG("[#] tcp.hdr_len = %u, not enough for TCP!\n", tcp_doff);
		return;
	}

	if (tcp_doff > packet_len) {
		DEBUG("[#] tcp.hdr_len = %u, past end of packet!\n", tcp_doff);
		return;
	}

	pk.tot_hdr += tcp_doff;

	pk.sport = ntohs(RD16(tcp->sport));
	pk.dport = ntohs(RD16(tcp->dport));

	pk.tcp_type = tcp->flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST);

	// NUL, SYN+FIN, SYN+RST, FIN+RST, etc, should go to /dev/null.
	if (((tcp->flags & TCP_SYN) && (tcp->flags & (TCP_FIN | TCP_RST))) ||
		((tcp->flags & TCP_FIN) && (tcp->flags & TCP_RST)) ||
		!pk.tcp_type) {

		DEBUG("[#] Silly combination of TCP flags: 0x%02x.\n", tcp->flags);
		return;
	}

	pk.win = ntohs(RD16(tcp->win));
	pk.seq = ntohl(RD32(tcp->seq));

	// Take note of miscellanous features and quirks.
	if ((tcp->flags & (TCP_ECE | TCP_CWR)) || (tcp->doff_rsvd & TCP_NS_RES)) {
		pk.quirks |= QUIRK_ECN;
	}

	if (!pk.seq) {
		pk.quirks |= QUIRK_ZERO_SEQ;
	}

	if (tcp->flags & TCP_ACK) {
		if (!RD32(tcp->ack)) {
			pk.quirks |= QUIRK_ZERO_ACK;
		}
	} else {

		/* A good proportion of RSTs tend to have "illegal" ACK numbers, so
		 * ignore these. */

		if (RD32(tcp->ack) && !(tcp->flags & TCP_RST)) {
			DEBUG("[#] Non-zero ACK on a non-ACK packet: 0x%08x.\n",
				  ntohl(RD32(tcp->ack)));

			pk.quirks |= QUIRK_NZ_ACK;
		}
	}

	if (tcp->flags & TCP_URG) {
		pk.quirks |= QUIRK_URG;
	} else {
		if (RD16(tcp->urg)) {
			DEBUG("[#] Non-zero UPtr on a non-URG packet: 0x%08x.\n",
				  ntohl(RD16(tcp->urg)));

			pk.quirks |= QUIRK_NZ_URG;
		}
	}

	if (tcp->flags & TCP_PUSH) {
		pk.quirks |= QUIRK_PUSH;
	}

	// Handle payload data.
	if (tcp_doff == packet_len) {
		pk.payload = nullptr;
		pk.pay_len = 0;
	} else {
		pk.payload = data + tcp_doff;
		pk.pay_len = packet_len - tcp_doff;
	}

	/* --------------------
	 * TCP option parsing *
	 * -------------------*/
	const uint8_t *opt_end = data + tcp_doff; // First byte of non-option data
	data                   = reinterpret_cast<const uint8_t *>(tcp + 1);

	pk.opt_layout.clear();
	pk.opt_eol_pad = 0;
	pk.mss         = 0;
	pk.wscale      = 0;
	pk.ts1         = 0;

	/* Option parsing problems are non-fatal, but we want to keep track of
	 * them to spot buggy TCP stacks. */

	while (data < opt_end) {

		pk.opt_layout.push_back(*data);

		switch (*data++) {
		case TCPOPT_EOL:

			/* EOL is a single-byte option that aborts further option parsing.
			 * Take note of how many bytes of option data are left, and if any
			 * of them are non-zero. */

			pk.opt_eol_pad = opt_end - data;

			while (data < opt_end && !*data++) {
			}

			if (data != opt_end) {
				pk.quirks |= QUIRK_OPT_EOL_NZ;
				data = opt_end;
			}

			break;
		case TCPOPT_NOP:
			// NOP is a single-byte option that does nothing.
			break;
		case TCPOPT_MAXSEG:
			// MSS is a four-byte option with specified size.
			if (data + 3 > opt_end) {
				DEBUG("[#] MSS option would end past end of header (%ld left).\n",
					  opt_end - data);
				goto abort_options;
			}

			if (*data != 4) {
				DEBUG("[#] MSS option expected to have 4 bytes, not %u.\n", *data);
				pk.quirks |= QUIRK_OPT_BAD;
			}

			pk.mss = ntohs(RD16p(data + 1));
			data += 3;
			break;
		case TCPOPT_WSCALE:
			// WS is a three-byte option with specified size.
			if (data + 2 > opt_end) {
				DEBUG("[#] WS option would end past end of header (%ld left).\n",
					  opt_end - data);
				goto abort_options;
			}

			if (*data != 3) {
				DEBUG("[#] WS option expected to have 3 bytes, not %u.\n", *data);
				pk.quirks |= QUIRK_OPT_BAD;
			}

			pk.wscale = data[1];

			if (pk.wscale > 14) {
				pk.quirks |= QUIRK_OPT_EXWS;
			}

			data += 2;
			break;
		case TCPOPT_SACKOK:

			// SACKOK is a two-byte option with specified size.
			if (data + 1 > opt_end) {
				DEBUG("[#] SACKOK option would end past end of header (%ld left).\n",
					  opt_end - data);
				goto abort_options;
			}

			if (*data != 2) {
				DEBUG("[#] SACKOK option expected to have 2 bytes, not %u.\n", *data);
				pk.quirks |= QUIRK_OPT_BAD;
			}
			data++;
			break;
		case TCPOPT_SACK:
			/* SACK is a variable-length option of 10 to 34 bytes.
			 * Because we don't know the size any better, we need to bail out
			 * if it looks wonky. */
			if (data == opt_end) {
				DEBUG("[#] SACK option without room for length field.");
				goto abort_options;
			}

			if (*data < 10 || *data > 34) {
				DEBUG("[#] SACK length out of range (%u), bailing out.\n", *data);
				goto abort_options;
			}

			if (data - 1 + *data > opt_end) {
				DEBUG("[#] SACK option (len %u) is too long (%ld left).\n",
					  *data, opt_end - data);
				goto abort_options;
			}
			data += *data - 1;
			break;
		case TCPOPT_TSTAMP:

			// Timestamp is a ten-byte option with specified size.
			if (data + 9 > opt_end) {
				DEBUG("[#] TStamp option would end past end of header (%ld left).\n",
					  opt_end - data);
				goto abort_options;
			}

			if (*data != 10) {
				DEBUG("[#] TStamp option expected to have 10 bytes, not %u.\n",
					  *data);
				pk.quirks |= QUIRK_OPT_BAD;
			}

			pk.ts1 = ntohl(RD32p(data + 1));

			if (!pk.ts1) {
				pk.quirks |= QUIRK_OPT_ZERO_TS1;
			}

			if (pk.tcp_type == TCP_SYN && RD32p(data + 5)) {

				DEBUG("[#] Non-zero second timestamp: 0x%08x.\n",
					  ntohl(RD32p(data + 5)));

				pk.quirks |= QUIRK_OPT_NZ_TS2;
			}

			data += 9;
			break;
		default:
			// Unknown option, presumably with specified size.
			if (data == opt_end) {
				DEBUG("[#] Unknown option 0x%02x without room for length field.",
					  data[-1]);
				goto abort_options;
			}

			if (*data < 2 || *data > 40) {
				DEBUG("[#] Unknown option 0x%02x has invalid length %u.\n",
					  data[-1], *data);
				goto abort_options;
			}

			if (data - 1 + *data > opt_end) {
				DEBUG("[#] Unknown option 0x%02x (len %u) is too long (%ld left).\n",
					  data[-1], *data, opt_end - data);
				goto abort_options;
			}

			data += *data - 1;
		}
	}

	if (data != opt_end) {
	abort_options:

		DEBUG("[#] Option parsing aborted (cnt = %lu, remainder = %ld).\n",
			  pk.opt_layout.size(), opt_end - data);

		pk.quirks |= QUIRK_OPT_BAD;
	}

	flow_dispatch(&pk);
}

// Look up host data.
host_data *process_context_t::lookup_host(const uint8_t *addr, uint8_t ip_ver) {

	uint32_t bucket = get_host_bucket(addr, ip_ver);
	host_data *h    = host_b_[bucket];

	while (h) {

		if (ip_ver == h->ip_ver &&
			!memcmp(addr, h->addr, (h->ip_ver == IP_VER4) ? 4 : 16)) {
			return h;
		}

		h = h->next;
	}

	return nullptr;
}

// Add NAT score, check if alarm due.
void process_context_t::add_nat_score(bool to_srv, const packet_flow *f, uint16_t reason, uint8_t score) {

	host_data *hd   = nullptr;
	uint8_t *scores = nullptr;
	uint32_t i      = 0;
	uint8_t over_5  = 0;
	uint8_t over_2  = 0;
	uint8_t over_1  = 0;
	uint8_t over_0  = 0;

	if (to_srv) {

		hd     = f->client;
		scores = hd->cli_scores;

	} else {

		hd     = f->server;
		scores = hd->srv_scores;
	}

	memmove(scores, scores + 1, NAT_SCORES - 1);
	scores[NAT_SCORES - 1] = score;
	hd->nat_reasons |= reason;

	if (!score) {
		return;
	}

	for (i = 0; i < NAT_SCORES; i++) {
		uint8_t temp_score = scores[i];
		if (temp_score >= 6) {
			over_5++;
			over_2++;
			over_1++;
			over_0++;
		} else if (temp_score >= 3 && temp_score <= 5) {
			over_2++;
			over_1++;
			over_0++;
		} else if (temp_score == 2) {
			over_1++;
			over_0++;
		} else if (temp_score == 1) {
			over_0++;
		}
	}

	if (over_5 > 2 || over_2 > 4 || over_1 > 6 || over_0 > 8) {

		ctx_->begin_observation("ip sharing", 2, to_srv, f);

		reason = hd->nat_reasons;

		hd->last_nat = get_unix_time();

		memset(scores, 0, NAT_SCORES);
		hd->nat_reasons = 0;

	} else {

		// Wait for something more substantial.
		if (score == 1) {
			return;
		}

		ctx_->begin_observation("host change", 2, to_srv, f);

		hd->last_chg = get_unix_time();
	}

	std::ostringstream ss;
	if (reason & NAT_APP_SIG) {
		ss << (" app_vs_os");
	}
	if (reason & NAT_OS_SIG) {
		ss << (" os_diff");
	}
	if (reason & NAT_UNK_DIFF) {
		ss << (" sig_diff");
	}
	if (reason & NAT_TO_UNK) {
		ss << (" x_known");
	}
	if (reason & NAT_TS) {
		ss << (" tstamp");
	}
	if (reason & NAT_TTL) {
		ss << (" ttl");
	}
	if (reason & NAT_PORT) {
		ss << (" port");
	}
	if (reason & NAT_MSS) {
		ss << (" mtu");
	}
	if (reason & NAT_FUZZY) {
		ss << (" fuzzy");
	}
	if (reason & NAT_APP_VIA) {
		ss << (" via");
	}
	if (reason & NAT_APP_DATE) {
		ss << (" date");
	}
	if (reason & NAT_APP_LB) {
		ss << (" srv_sig_lb");
	}
	if (reason & NAT_APP_UA) {
		ss << (" ua_vs_os");
	}

	std::string rea = ss.str();

	ctx_->observation_field("reason", !rea.empty() ? (rea.c_str() + 1) : nullptr);

	report_observation(ctx_, "raw_hits", "%u,%u,%u,%u", over_5, over_2, over_1, over_0);
}

// Verify if tool class (called from modules).
void process_context_t::verify_tool_class(bool to_srv, const packet_flow *f, const std::vector<uint32_t> &sys) {

	host_data *hd = nullptr;
	if (to_srv) {
		hd = f->client;
	} else {
		hd = f->server;
	}

	/* No existing data; although there is perhaps some value in detecting
	 * app-only conflicts in absence of other info, it's probably OK to just
	 * wait until more data becomes available. */
	if (hd->last_class_id == InvalidId) {
		return;
	}

	uint32_t i = 0;
	for (i = 0; i < sys.size(); i++) {
		if ((sys[i] & SYS_CLASS_FLAG)) {
			if (SYS_NF(sys[i]) == hd->last_class_id) {
				break;
			}
		} else {
			if (SYS_NF(sys[i]) == hd->last_name_id) {
				break;
			}
		}
	}

	// Oops, a mismatch.
	if (i == sys.size()) {
		DEBUG("[#] Detected app not supposed to run on host OS.\n");
		add_nat_score(to_srv, f, NAT_APP_SIG, 4);
	} else {
		DEBUG("[#] Detected app supported on host OS.\n");
		add_nat_score(to_srv, f, 0, 0);
	}
}

// Clean up everything.
void process_context_t::destroy_all_hosts() {
	while (flow_by_age_) {
		destroy_flow(flow_by_age_);
	}

	while (host_by_age_) {
		destroy_host(host_by_age_);
	}
}
