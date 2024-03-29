/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef P0F_FP_MTU_H_
#define P0F_FP_MTU_H_

#include "process.h"
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

struct packet_data;
struct packet_flow;

// Record for a TCP signature read from p0f.fp:
struct mtu_sig_record {
	std::optional<std::string> name;
	uint16_t mtu;
};

struct mtu_context_t {
public:
	mtu_context_t(libp0f *ctx)
		: ctx_(ctx) {}

public:
	void mtu_register_sig(const std::optional<std::string> &name, std::string_view val, uint32_t line_no);
	void fingerprint_mtu(bool to_srv, packet_data *pk, packet_flow *f);

private:
	std::vector<mtu_sig_record> sigs_[SIG_BUCKETS];

private:
	libp0f *ctx_ = nullptr;
};

#endif
