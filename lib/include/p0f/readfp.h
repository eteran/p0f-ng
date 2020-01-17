/*
   p0f - p0f.fp file parser
   ------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_READFP_H_
#define HAVE_READFP_H_

#include <cstdint>
#include <string>
#include <vector>
#include "string_view.h"

// List of fingerprinting modules:
#define CF_MOD_TCP 0x00  // fp_tcp.c
#define CF_MOD_MTU 0x01  // fp_mtu.c
#define CF_MOD_HTTP 0x02 // fp_http.c

// Parser states:
#define CF_NEED_SECT 0x00  // Waiting for [...] or 'classes'
#define CF_NEED_LABEL 0x01 // Waiting for 'label'
#define CF_NEED_SYS 0x02   // Waiting for 'sys'
#define CF_NEED_SIG 0x03   // Waiting for signatures, if any.

// Flag to distinguish OS class and name IDs
#define SYS_CLASS_FLAG (1u << 31)

constexpr int32_t SYS_NF(uint32_t x) {
	return (x & ~SYS_CLASS_FLAG);
}

void read_config(const char *fname);
int32_t lookup_name_id(string_view name);

struct fp_context_t {
	uint32_t sig_cnt = 0; // Total number of p0f.fp sigs

	uint8_t state      = CF_NEED_SECT; // Parser state (CF_NEED_*)
	uint8_t mod_type   = 0;            // Current module (CF_MOD_*)
	uint8_t mod_to_srv = 0;            // Traffic direction
	uint8_t generic    = 0;            // Generic signature?

	int32_t sig_class = 0;       // Signature class ID (-1 = userland)
	int32_t sig_name = 0;       // Signature name
	char *sig_flavor  = nullptr; // Signature flavor

	uint32_t *cur_sys    = nullptr; // Current 'sys' values
	uint32_t cur_sys_cnt = 0;       // Number of 'sys' entries

	uint32_t label_id = 0; // Current label ID
	uint32_t line_no  = 0; // Current line number

	// Map of OS classes
	std::vector<std::string> fp_os_classes;
	std::vector<char *> fp_os_names;
};

extern fp_context_t fp_context;

#endif
