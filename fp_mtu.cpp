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

#include "config.h"
#include "debug.h"
#include "fp_mtu.h"
#include "p0f.h"
#include "process.h"
#include "readfp.h"
#include "tcp.h"

struct mtu_context_t {
	struct mtu_sig_record *sigs[SIG_BUCKETS];
	uint32_t sig_cnt[SIG_BUCKETS];
};

static mtu_context_t mtu_context;

// Register a new MTU signature.
void mtu_register_sig(char *name, char *val, uint32_t line_no) {

	char *nxt = val;
	int32_t mtu;
	uint32_t bucket;

	while (isdigit(*nxt))
		nxt++;

	if (nxt == val || *nxt)
		FATAL("Malformed MTU value in line %u.", line_no);

	mtu = atoi(val);

	if (mtu <= 0 || mtu > 65535)
		FATAL("Malformed MTU value in line %u.", line_no);

	bucket = mtu % SIG_BUCKETS;

	mtu_context.sigs[bucket] = static_cast<struct mtu_sig_record *>(realloc(mtu_context.sigs[bucket], (mtu_context.sig_cnt[bucket] + 1) * sizeof(struct mtu_sig_record)));

	mtu_context.sigs[bucket][mtu_context.sig_cnt[bucket]].mtu  = mtu;
	mtu_context.sigs[bucket][mtu_context.sig_cnt[bucket]].name = name;

	mtu_context.sig_cnt[bucket]++;
}

void fingerprint_mtu(uint8_t to_srv, struct packet_data *pk, struct packet_flow *f, libp0f_context_t *libp0f_context) {

	uint32_t bucket, i, mtu;

	if (!pk->mss || f->sendsyn) return;

	libp0f_context->start_observation("mtu", 2, to_srv, f);

	if (pk->ip_ver == IP_VER4)
		mtu = pk->mss + MIN_TCP4;
	else
		mtu = pk->mss + MIN_TCP6;

	bucket = (mtu) % SIG_BUCKETS;

	for (i = 0; i < mtu_context.sig_cnt[bucket]; i++)
		if (mtu_context.sigs[bucket][i].mtu == mtu) break;

	if (i == mtu_context.sig_cnt[bucket])
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
