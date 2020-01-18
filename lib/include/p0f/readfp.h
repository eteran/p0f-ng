/*
   p0f - p0f.fp file parser
   ------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_READFP_H_
#define HAVE_READFP_H_

#include "ext/optional.h"
#include "ext/string_view.h"
#include <cstdint>
#include <string>
#include <vector>

// List of fingerprinting modules:
enum Modules : uint8_t {
	CF_MOD_TCP  = 0x00, // fp_tcp.c
	CF_MOD_MTU  = 0x01, // fp_mtu.c
	CF_MOD_HTTP = 0x02, // fp_http.c
};

// Parser states:
enum States : uint8_t {
	CF_NEED_SECT  = 0x00, // Waiting for [...] or 'classes'
	CF_NEED_LABEL = 0x01, // Waiting for 'label'
	CF_NEED_SYS   = 0x02, // Waiting for 'sys'
	CF_NEED_SIG   = 0x03, // Waiting for signatures, if any.
};

// Flag to distinguish OS class and name IDs
constexpr uint32_t SYS_CLASS_FLAG = 1u << 31;

constexpr uint32_t SYS_NF(uint32_t x) {
	return (x & ~SYS_CLASS_FLAG);
}

struct fp_context_t {
public:
	void read_config(const char *fname);
	uint32_t lookup_name_id(ext::string_view name);

private:
	void config_parse_classes(ext::string_view value);
	void config_parse_label(const std::string &value);
	void config_parse_sys(ext::string_view value);
	void config_parse_line(ext::string_view line);
	uint32_t lookup_name_id(const char *name, size_t len);

public:
	uint32_t sig_cnt_ = 0; // Total number of p0f.fp sigs

	uint8_t state_      = CF_NEED_SECT; // Parser state (CF_NEED_*)
	uint8_t mod_type_   = 0;            // Current module (CF_MOD_*)
	uint8_t mod_to_srv_ = 0;            // Traffic direction
	uint8_t generic_    = 0;            // Generic signature?

	uint32_t sig_class_ = 0;                // Signature class ID (-1 = userland)
	uint32_t sig_name_  = 0;                // Signature name
	ext::optional<std::string> sig_flavor_; // Signature flavor

	std::vector<uint32_t> cur_sys_; // Current 'sys' values

	uint32_t label_id_ = 0; // Current label ID
	uint32_t line_no_  = 0; // Current line number

	// Map of OS classes
	std::vector<std::string> fp_os_classes_;
	std::vector<std::string> fp_os_names_;
};

extern fp_context_t fp_context;

#endif
