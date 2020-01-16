/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/types.h>

#include "p0f/config.h"
#include "p0f/debug.h"
#include "p0f/fp_mtu.h"
#include "p0f/p0f.h"
#include "p0f/process.h"
#include "p0f/readfp.h"
#include "p0f/tcp.h"
#include "p0f/util.h"
#include "p0f/parser.h"

namespace {

struct mtu_context_t {
	std::vector<struct mtu_sig_record> sigs[SIG_BUCKETS];
};

mtu_context_t mtu_context;

}

// Register a new MTU signature.
void mtu_register_sig(char *name, const std::string &val, uint32_t line_no) {

	parser in(val);

	std::string mtu_str;
	if (!in.match([](char ch) { return isdigit(ch); }, &mtu_str)) {
		FATAL("Malformed MTU value in line %u.", line_no);
	}
	int32_t mtu = atoi(mtu_str.c_str());

	if (mtu <= 0 || mtu > 65535)
		FATAL("Malformed MTU value in line %u.", line_no);

	uint32_t bucket = mtu % SIG_BUCKETS;

	struct mtu_sig_record sig;
	sig.mtu  = mtu;
	sig.name = name;

	mtu_context.sigs[bucket].push_back(sig);
}

void fingerprint_mtu(bool to_srv, struct packet_data *pk, struct packet_flow *f, libp0f_context_t *libp0f_context) {

	uint32_t bucket;
	uint32_t i;
	uint32_t mtu;

	if (!pk->mss || f->sendsyn)
		return;

	libp0f_context->start_observation("mtu", 2, to_srv, f);

	if (pk->ip_ver == IP_VER4)
		mtu = pk->mss + MIN_TCP4;
	else
		mtu = pk->mss + MIN_TCP6;

	bucket = (mtu) % SIG_BUCKETS;

	for (i = 0; i < mtu_context.sigs[bucket].size(); i++)
		if (mtu_context.sigs[bucket][i].mtu == mtu)
			break;

	if (i == mtu_context.sigs[bucket].size())
		libp0f_context->observation_field("link", nullptr);
	else {

		libp0f_context->observation_field("link", mtu_context.sigs[bucket][i].name);

		if (to_srv)
			f->client->link_type = mtu_context.sigs[bucket][i].name;
		else
			f->server->link_type = mtu_context.sigs[bucket][i].name;
	}

	observf(libp0f_context, "raw_mtu", "%u", mtu);
}
