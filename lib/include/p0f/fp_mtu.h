/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_FP_MTU_H_
#define HAVE_FP_MTU_H_

#include "process.h"
#include "string_view.h"
#include <cstdint>

struct packet_data;
struct packet_flow;

// Record for a TCP signature read from p0f.fp:
struct mtu_sig_record {
	const char *name;
	uint16_t mtu;
};

void mtu_register_sig(char *name, string_view val, uint32_t line_no);
void fingerprint_mtu(bool to_srv, struct packet_data *pk, struct packet_flow *f, libp0f_context_t *libp0f_context);

#endif
