/*
   p0f - p0f.fp file parser
   ------------------------

   Every project has this one really ugly C file. This is ours.

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "p0f/config.h"
#include "p0f/debug.h"
#include "p0f/ext/string_view.h"
#include "p0f/fp_http.h"
#include "p0f/fp_mtu.h"
#include "p0f/fp_tcp.h"
#include "p0f/libp0f.h"
#include "p0f/readfp.h"
#include "p0f/util.h"
#include "parser.h"

namespace {

bool string_equals(ext::string_view lhs, ext::string_view rhs) {
	if (lhs.size() != rhs.size()) {
		return false;
	}

	return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), [](char a, char b) {
		return tolower(a) == tolower(b);
	});
}

}

// Parse 'classes' parameter by populating fp_os_classes_.
void fp_context_t::config_parse_classes(ext::string_view value) {

	parser in(value);
	do {
		in.consume_whitespace();

		std::string class_name;
		if (!in.match([](char ch) { return isalnum(ch); }, &class_name)) {
			FATAL("Malformed class entry in line %u.", line_no_);
		}

		os_classes_.push_back(std::move(class_name));

		in.consume_whitespace();
	} while (in.match(','));

	if (!in.eof()) {
		FATAL("Malformed class entry in line %u.", line_no_);
	}
}

// Parse 'label' parameter by looking up ID and recording name / flavor.
void fp_context_t::config_parse_label(ext::string_view value) {

	// Simplified handling for [mtu] signatures.
	if (mod_type_ == CF_MOD_MTU) {
		if (value.empty()) {
			FATAL("Empty MTU label in line %u.\n", line_no_);
		}

		sig_flavor_ = value.to_string();
		return;
	}

	parser in(value);

	// type
	if (in.match('g')) {
		generic_ = 1;
	} else if (in.match('s')) {
		generic_ = 0;
	} else {
		FATAL("Malformed class entry in line %u.", line_no_);
	}

	if (!in.match(':')) {
		FATAL("Malformed class entry in line %u.", line_no_);
	}

	// class
	std::string class_name;
	if (in.match('!')) {
		sig_class_ = InvalidId;
	} else if (in.match([](char ch) { return isalnum(ch); }, &class_name)) {
		auto it = std::find_if(os_classes_.begin(), os_classes_.end(), [&class_name](ext::string_view os_class) {
			return string_equals(class_name, os_class);
		});

		if (it == os_classes_.end()) {
			FATAL("Unknown class '%s' in line %u.", class_name.c_str(), line_no_);
		}

		sig_class_ = std::distance(os_classes_.begin(), it);
	}

	if (!in.match(':')) {
		FATAL("Malformed class entry in line %u.", line_no_);
	}

	// name
	std::string name;
	if (!in.match([](char ch) { return isalnum(ch) || strchr(NAME_CHARS, ch); }, &name)) {
		FATAL("Malformed name in line %u.", line_no_);
	}

	sig_name_ = lookup_name_id(name);

	if (!in.match(':')) {
		FATAL("Malformed class entry in line %u.", line_no_);
	}

	// flavor
	std::string flavor;
	if (in.match_any(&flavor)) {
		sig_flavor_ = flavor;
	} else {
		sig_flavor_ = {};
	}

	++label_id_;
}

// Parse 'sys' parameter into cur_sys_[].
void fp_context_t::config_parse_sys(ext::string_view value) {

	cur_sys_.clear();

	parser in(value);
	do {
		in.consume_whitespace();

		const bool is_cl = in.match('@');

		std::string class_name;
		if (!in.match([](char ch) { return isalnum(ch) || (strchr(NAME_CHARS, ch)); }, &class_name)) {
			FATAL("Malformed sys entry in line %u.", line_no_);
		}

		uint32_t i;
		if (is_cl) {

			for (i = 0; i < os_classes_.size(); i++) {
				if (string_equals(class_name, os_classes_[i])) {
					break;
				}
			}

			if (i == os_names_.size()) {
				FATAL("Unknown class '%s' in line %u.", class_name.c_str(), line_no_);
			}

			i |= SYS_CLASS_FLAG;

		} else {

			for (i = 0; i < os_names_.size(); i++) {
				if (string_equals(class_name, os_names_[i])) {
					break;
				}
			}

			if (i == os_names_.size()) {
				os_names_.push_back(class_name);
			}
		}

		cur_sys_.push_back(i);

		in.consume_whitespace();
	} while (in.match(','));

	if (!in.eof()) {
		FATAL("Malformed sys entry in line %u.", line_no_);
	}
}

// Read p0f.fp line, dispatching it to fingerprinting modules as necessary.
void fp_context_t::config_parse_line(ext::string_view line) {

	parser in(line);

	// Special handling for [module:direction]...
	if (in.match('[')) {

		// Simplified case for [mtu].
		if (in.match("mtu]")) {
			mod_type_ = CF_MOD_MTU;
			state_    = CF_NEED_LABEL;
			return;
		}

		if (in.match("tcp")) {
			mod_type_ = CF_MOD_TCP;
		} else if (in.match("http")) {
			mod_type_ = CF_MOD_HTTP;
		} else {
			FATAL("Unrecognized fingerprinting module '%s' in line %u.", line.to_string().c_str(), line_no_);
		}

		if (!in.match(':')) {
			FATAL("Malformed section identifier in line %u.", line_no_);
		}

		if (in.match("request]")) {
			mod_to_srv_ = true;
		} else if (in.match("response]")) {
			mod_to_srv_ = false;
		} else {
			FATAL("Unrecognized traffic direction in line %u.", line_no_);
		}

		state_ = CF_NEED_LABEL;
		return;
	}

	// Everything else follows the 'name = value' approach.
	if (in.match("classes")) {

		if (state_ != CF_NEED_SECT) {
			FATAL("misplaced 'classes' in line %u.", line_no_);
		}

		in.consume_whitespace();

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", line_no_);
		}

		in.consume_whitespace();

		std::string value;
		in.match_any(&value);
		config_parse_classes(value);

	} else if (in.match("ua_os")) {

		if (state_ != CF_NEED_LABEL || mod_to_srv_ != 1 || mod_type_ != CF_MOD_HTTP) {
			FATAL("misplaced 'us_os' in line %u.", line_no_);
		}

		in.consume_whitespace();

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", line_no_);
		}

		in.consume_whitespace();

		std::string value;
		in.match_any(&value);

		ctx_->http_context.http_parse_ua(value, line_no_);

	} else if (in.match("label")) {

		/* We will drop sig_sys / sig_flavor_ on the floor if no
		 * signatures actually created, but it's not worth tracking that. */

		if (state_ != CF_NEED_LABEL && state_ != CF_NEED_SIG) {
			FATAL("misplaced 'label' in line %u.", line_no_);
		}

		in.consume_whitespace();

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", line_no_);
		}

		in.consume_whitespace();

		std::string value;
		in.match_any(&value);

		config_parse_label(value);

		if (mod_type_ != CF_MOD_MTU && sig_class_ == InvalidId) {
			state_ = CF_NEED_SYS;
		} else {
			state_ = CF_NEED_SIG;
		}

	} else if (in.match("sys")) {
		if (state_ != CF_NEED_SYS) {
			FATAL("Misplaced 'sys' in line %u.", line_no_);
		}

		in.consume_whitespace();

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", line_no_);
		}

		in.consume_whitespace();

		std::string value;
		in.match_any(&value);

		config_parse_sys(value);
		state_ = CF_NEED_SIG;
	} else if (in.match("sig")) {

		if (state_ != CF_NEED_SIG) {
			FATAL("Misplaced 'sig' in line %u.", line_no_);
		}

		in.consume_whitespace();

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", line_no_);
		}

		in.consume_whitespace();

		std::string value;
		in.match_any(&value);

		switch (mod_type_) {
		case CF_MOD_TCP:
			ctx_->tcp_context.tcp_register_sig(
				mod_to_srv_,
				generic_,
				sig_class_,
				sig_name_,
				sig_flavor_,
				label_id_,
				cur_sys_,
				value,
				line_no_);
			break;
		case CF_MOD_MTU:
			ctx_->mtu_context.mtu_register_sig(
				sig_flavor_,
				value,
				line_no_);
			break;
		case CF_MOD_HTTP:
			ctx_->http_context.http_register_sig(
				mod_to_srv_,
				generic_,
				sig_class_,
				sig_name_,
				sig_flavor_,
				label_id_,
				cur_sys_,
				value,
				line_no_);
			break;
		}

		++sig_cnt_;

	} else {
		FATAL("Unrecognized field '%s' in line %u.", line.to_string().c_str(), line_no_);
	}
}

// Look up or create OS or application id.
uint32_t fp_context_t::lookup_name_id(ext::string_view n) {

	uint32_t i;

	for (i = 0; i < os_names_.size(); i++) {
		if (string_equals(n, os_names_[i])) {
			break;
		}
	}

	if (i == os_names_.size()) {
		sig_name_ = os_names_.size();
		os_names_.push_back(n.to_string());
	}

	return i;
}

// Top-level file parsing.
void fp_context_t::read_config(const char *fname) {

	// If you put NUL in your p0f.fp... Well, sucks to be you.
	std::ifstream file(fname);
	for (std::string line; std::getline(file, line);) {

		++line_no_;

		ext::string_view line_view(line);
		while (!line_view.empty() && isblank(line_view[0])) {
			line_view.remove_prefix(1);
		}

		if (line_view.empty() || line_view[0] == ';') {
			continue;
		}

		config_parse_line(line_view);
	}

	if (!sig_cnt_) {
		SAYF("[!] No signatures found in '%s'.\n", fname);
	} else {
		SAYF("[+] Loaded %zu signature%s from '%s'.\n", sig_cnt_,
			 sig_cnt_ == 1 ? "" : "s", fname);
	}
}
