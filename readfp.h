/*
   p0f - p0f.fp file parser
   ------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_READFP_H_
#define HAVE_READFP_H_

#include <cstdint>

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
#define SYS_NF(_x) ((_x) & ~SYS_CLASS_FLAG)

struct libp0f_context_t;
void read_config(const char *fname, libp0f_context_t *libp0f_context);

uint32_t lookup_name_id(const char *name, uint8_t len, libp0f_context_t *libp0f_context);

#endif
