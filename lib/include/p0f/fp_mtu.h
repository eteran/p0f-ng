/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_FP_MTU_H_
#define HAVE_FP_MTU_H_

#include <cstdint>

// Record for a TCP signature read from p0f.fp:
struct mtu_sig_record {
	char *name;
	uint16_t mtu;
};

#include "process.h"

struct packet_data;
struct packet_flow;

void mtu_register_sig(char *name, const std::string &val, uint32_t line_no);
void fingerprint_mtu(bool to_srv, struct packet_data *pk, struct packet_flow *f, libp0f_context_t *libp0f_context);

#endif
