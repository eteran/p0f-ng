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
#include <string>
#include <unistd.h>
#include <vector>

#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "p0f/alloc-inl.h"
#include "p0f/config.h"
#include "p0f/debug.h"
#include "p0f/fp_http.h"
#include "p0f/fp_mtu.h"
#include "p0f/fp_tcp.h"
#include "p0f/p0f.h"
#include "p0f/parser.h"
#include "p0f/readfp.h"
#include "p0f/string_view.h"

fp_context_t fp_context;

namespace {

// Parse 'classes' parameter by populating fp_context.fp_os_classes.
void config_parse_classes(string_view value) {

	parser in(value);
	do {
		in.consume(" \t");

		std::string class_name;
		if (!in.match([](char ch) { return isalnum(ch); }, &class_name)) {
			FATAL("Malformed class entry in line %u.", fp_context.line_no);
		}

		fp_context.fp_os_classes.push_back(std::move(class_name));

		in.consume(" \t");
	} while (in.match(','));

	if (!in.eof()) {
		FATAL("Malformed class entry in line %u.", fp_context.line_no);
	}
}

// Parse 'label' parameter by looking up ID and recording name / flavor.
void config_parse_label(const std::string &value) {

	// Simplified handling for [mtu] signatures.
	if (fp_context.mod_type == CF_MOD_MTU) {
		if (value.empty())
			FATAL("Empty MTU label in line %u.\n", fp_context.line_no);

		fp_context.sig_flavor = ck_strdup(value.c_str());
		return;
	}

	parser in(value);

	// type
	if (in.match('g')) {
		fp_context.generic = 1;
	} else if (in.match('s')) {
		fp_context.generic = 0;
	} else {
		FATAL("Malformed class entry in line %u.", fp_context.line_no);
	}

	if (!in.match(':')) {
		FATAL("Malformed class entry in line %u.", fp_context.line_no);
	}

	// class
	std::string class_name;
	if (in.match('!')) {
		fp_context.sig_class = -1;
	} else if (in.match([](char ch) { return isalnum(ch); }, &class_name)) {
		auto it = std::find_if(fp_context.fp_os_classes.begin(), fp_context.fp_os_classes.end(), [&class_name](const std::string &os_class) {
			return strcasecmp(class_name.c_str(), os_class.c_str()) == 0;
		});

		if (it == fp_context.fp_os_classes.end()) {
			FATAL("Unknown class '%s' in line %u.", class_name.c_str(), fp_context.line_no);
		}

		fp_context.sig_class = std::distance(fp_context.fp_os_classes.begin(), it);
	}

	if (!in.match(':')) {
		FATAL("Malformed class entry in line %u.", fp_context.line_no);
	}

	// name
	std::string name;
	if (!in.match([](char ch) { return isalnum(ch) || strchr(NAME_CHARS, ch); }, &name)) {
		FATAL("Malformed name in line %u.", fp_context.line_no);
	}

	fp_context.sig_name = lookup_name_id(name.c_str(), name.size());

	if (!in.match(':')) {
		FATAL("Malformed class entry in line %u.", fp_context.line_no);
	}

	// flavor
	std::string flavor;
	if (in.match_any(&flavor)) {
		fp_context.sig_flavor = ck_strdup(flavor.c_str());
	} else {
		fp_context.sig_flavor = nullptr;
	}

	fp_context.label_id++;
}

// Parse 'sys' parameter into fp_context.cur_sys[].
void config_parse_sys(string_view value) {

	if (fp_context.cur_sys) {
		fp_context.cur_sys     = nullptr;
		fp_context.cur_sys_cnt = 0;
	}

	parser in(value);
	do {
		in.consume(" \t");

		const bool is_cl = in.match('@');

		std::string class_name;
		if (!in.match([](char ch) { return isalnum(ch) || (strchr(NAME_CHARS, ch)); }, &class_name)) {
			FATAL("Malformed sys entry in line %u.", fp_context.line_no);
		}

		uint32_t i;
		if (is_cl) {

			auto it = std::find_if(fp_context.fp_os_classes.begin(), fp_context.fp_os_classes.end(), [&class_name](const std::string &os_class) {
				return strcasecmp(class_name.c_str(), os_class.c_str()) == 0;
			});

			if (it == fp_context.fp_os_classes.end())
				FATAL("Unknown class '%s' in line %u.", class_name.c_str(), fp_context.line_no);

			i = std::distance(fp_context.fp_os_classes.begin(), it) | SYS_CLASS_FLAG;

		} else {

			for (i = 0; i < fp_context.fp_os_names.size(); i++) {
				if (!strcasecmp(class_name.c_str(), fp_context.fp_os_names[i])) {
					break;
				}
			}

			if (i == fp_context.fp_os_names.size()) {
				fp_context.fp_os_names.push_back(ck_memdup_str(class_name.c_str(), class_name.size()));
			}
		}

		fp_context.cur_sys                           = static_cast<uint32_t *>(realloc(fp_context.cur_sys, (fp_context.cur_sys_cnt + 1) * sizeof(uint32_t)));
		fp_context.cur_sys[fp_context.cur_sys_cnt++] = i;

		in.consume(" \t");
	} while (in.match(','));

	if (!in.eof()) {
		FATAL("Malformed sys entry in line %u.", fp_context.line_no);
	}
}

// Read p0f.fp line, dispatching it to fingerprinting modules as necessary.
void config_parse_line(string_view line) {

	parser in(line);

	// Special handling for [module:direction]...
	if (in.match('[')) {

		// Simplified case for [mtu].
		if (in.match("mtu]")) {
			fp_context.mod_type = CF_MOD_MTU;
			fp_context.state    = CF_NEED_LABEL;
			return;
		}

		if (in.match("tcp")) {
			fp_context.mod_type = CF_MOD_TCP;
		} else if (in.match("http")) {
			fp_context.mod_type = CF_MOD_HTTP;
		} else {
			FATAL("Unrecognized fingerprinting module '%s' in line %u.", std::string(line.begin(), line.end()).c_str(), fp_context.line_no);
		}

		if (!in.match(':')) {
			FATAL("Malformed section identifier in line %u.", fp_context.line_no);
		}

		if (in.match("request]")) {
			fp_context.mod_to_srv = 1;
		} else if (in.match("response]")) {
			fp_context.mod_to_srv = 0;
		} else {
			FATAL("Unrecognized traffic direction in line %u.", fp_context.line_no);
		}

		fp_context.state = CF_NEED_LABEL;
		return;
	}

	// Everything else follows the 'name = value' approach.
	if (in.match("classes")) {

		if (fp_context.state != CF_NEED_SECT)
			FATAL("misplaced 'classes' in line %u.", fp_context.line_no);

		in.consume(" \t");

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", fp_context.line_no);
		}

		in.consume(" \t");

		std::string value;
		in.match_any(&value);
		config_parse_classes(value);

	} else if (in.match("ua_os")) {

		if (fp_context.state != CF_NEED_LABEL || fp_context.mod_to_srv != 1 || fp_context.mod_type != CF_MOD_HTTP)
			FATAL("misplaced 'us_os' in line %u.", fp_context.line_no);

		in.consume(" \t");

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", fp_context.line_no);
		}

		in.consume(" \t");

		std::string value;
		in.match_any(&value);

		http_parse_ua(value, fp_context.line_no);

	} else if (in.match("label")) {

		/* We will drop sig_sys / fp_context.sig_flavor on the floor if no
		 * signatures actually created, but it's not worth tracking that. */

		if (fp_context.state != CF_NEED_LABEL && fp_context.state != CF_NEED_SIG)
			FATAL("misplaced 'label' in line %u.", fp_context.line_no);

		in.consume(" \t");

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", fp_context.line_no);
		}

		in.consume(" \t");

		std::string value;
		in.match_any(&value);

		config_parse_label(value);

		if (fp_context.mod_type != CF_MOD_MTU && fp_context.sig_class < 0)
			fp_context.state = CF_NEED_SYS;
		else
			fp_context.state = CF_NEED_SIG;

	} else if (in.match("sys")) {
		if (fp_context.state != CF_NEED_SYS)
			FATAL("Misplaced 'sys' in line %u.", fp_context.line_no);

		in.consume(" \t");

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", fp_context.line_no);
		}

		in.consume(" \t");

		std::string value;
		in.match_any(&value);

		config_parse_sys(value);
		fp_context.state = CF_NEED_SIG;
	} else if (in.match("sig")) {

		if (fp_context.state != CF_NEED_SIG)
			FATAL("Misplaced 'sig' in line %u.", fp_context.line_no);

		in.consume(" \t");

		if (!in.match('=')) {
			FATAL("Unexpected statement in line %u.", fp_context.line_no);
		}

		in.consume(" \t");

		std::string value;
		in.match_any(&value);

		switch (fp_context.mod_type) {
		case CF_MOD_TCP:
			tcp_register_sig(
				fp_context.mod_to_srv,
				fp_context.generic,
				fp_context.sig_class,
				fp_context.sig_name,
				fp_context.sig_flavor,
				fp_context.label_id,
				fp_context.cur_sys,
				fp_context.cur_sys_cnt,
				value,
				fp_context.line_no);
			break;
		case CF_MOD_MTU:
			mtu_register_sig(
				fp_context.sig_flavor,
				value,
				fp_context.line_no);
			break;
		case CF_MOD_HTTP:
			http_register_sig(
				fp_context.mod_to_srv,
				fp_context.generic,
				fp_context.sig_class,
				fp_context.sig_name,
				fp_context.sig_flavor,
				fp_context.label_id,
				fp_context.cur_sys,
				fp_context.cur_sys_cnt,
				value,
				fp_context.line_no);
			break;
		}

		fp_context.sig_cnt++;

	} else {
		FATAL("Unrecognized field '%s' in line %u.", std::string(line.begin(), line.end()).c_str(), fp_context.line_no);
	}
}

}

// Look up or create OS or application id.
uint32_t lookup_name_id(const char *name, uint8_t len) {

	uint32_t i;

	for (i = 0; i < fp_context.fp_os_names.size(); i++)
		if (!strncasecmp(name, fp_context.fp_os_names[i], len) && !fp_context.fp_os_names[i][len]) break;

	if (i == fp_context.fp_os_names.size()) {
		fp_context.sig_name = fp_context.fp_os_names.size();
		fp_context.fp_os_names.push_back(ck_memdup_str(name, len));
	}

	return i;
}

// Top-level file parsing.
void read_config(const char *fname) {

	struct stat st;
	char *data;
	char *cur;

	int f = open(fname, O_RDONLY);
	if (f < 0)
		PFATAL("Cannot open '%s' for reading.", fname);

	if (fstat(f, &st))
		PFATAL("fstat() on '%s' failed.", fname);

	if (!st.st_size) {
		close(f);
		goto end_fp_read;
	}

	data = static_cast<char *>(calloc(st.st_size + 1, 1));
	cur  = data;

	if (read(f, data, st.st_size) != st.st_size) {
		FATAL("Short read from '%s'.", fname);
	}

	data[st.st_size] = 0;
	close(f);

	// If you put NUL in your p0f.fp... Well, sucks to be you.
	while (1) {
		char *eol;

		fp_context.line_no++;

		while (isblank(*cur))
			cur++;

		eol = cur;
		while (*eol && *eol != '\n')
			eol++;

		if (*cur != ';' && cur != eol) {
			char *line = ck_memdup_str(cur, eol - cur);
			config_parse_line(line);
			free(line);
		}

		if (!*eol) break;

		cur = eol + 1;
	}

	free(data);

end_fp_read:

	if (!fp_context.sig_cnt)
		SAYF("[!] No signatures found in '%s'.\n", fname);
	else
		SAYF("[+] Loaded %u signature%s from '%s'.\n", fp_context.sig_cnt,
			 fp_context.sig_cnt == 1 ? "" : "s", fname);
}
