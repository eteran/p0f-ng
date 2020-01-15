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
#include "p0f/readfp.h"

fp_context_t fp_context;

namespace {

// Parse 'classes' parameter by populating fp_context.fp_os_classes.
void config_parse_classes(char *val) {

	while (*val) {

		char *nxt;

		while (isblank(*val) || *val == ',')
			val++;

		nxt = val;

		while (isalnum(*nxt))
			nxt++;

		if (nxt == val || (*nxt && *nxt != ','))
			FATAL("Malformed class entry in line %u.", fp_context.line_no);

		fp_context.fp_os_classes.push_back(std::string(val, nxt - val));
		val = nxt;
	}
}

// Parse 'label' parameter by looking up ID and recording name / flavor.
void config_parse_label(char *val) {

	char *nxt;

	// Simplified handling for [mtu] signatures.
	if (fp_context.mod_type == CF_MOD_MTU) {
		if (!*val)
			FATAL("Empty MTU label in line %u.\n", fp_context.line_no);

		fp_context.sig_flavor = ck_strdup(val);
		return;
	}

	if (*val == 'g')
		fp_context.generic = 1;
	else if (*val == 's')
		fp_context.generic = 0;
	else
		FATAL("Malformed class entry in line %u.", fp_context.line_no);

	if (val[1] != ':')
		FATAL("Malformed class entry in line %u.", fp_context.line_no);

	val += 2;

	nxt = val;
	while (isalnum(*nxt) || *nxt == '!')
		nxt++;

	if (nxt == val || *nxt != ':')
		FATAL("Malformed class entry in line %u.", fp_context.line_no);

	if (*val == '!' && val[1] == ':') {
		fp_context.sig_class = -1;
	} else {

		*nxt = 0;

		auto it = std::find_if(fp_context.fp_os_classes.begin(), fp_context.fp_os_classes.end(), [val](const std::string &os_class) {
			return strcasecmp(val, os_class.c_str()) == 0;
		});

		if (it == fp_context.fp_os_classes.end()) {
			FATAL("Unknown class '%s' in line %u.", val, fp_context.line_no);
		}

		fp_context.sig_class = std::distance(fp_context.fp_os_classes.begin(), it);
	}

	nxt++;
	val = nxt;
	while (isalnum(*nxt) || (*nxt && strchr(NAME_CHARS, *nxt)))
		nxt++;

	if (nxt == val || *nxt != ':')
		FATAL("Malformed name in line %u.", fp_context.line_no);

	fp_context.sig_name = lookup_name_id(val, nxt - val);

	if (nxt[1])
		fp_context.sig_flavor = ck_strdup(nxt + 1);
	else
		fp_context.sig_flavor = nullptr;

	fp_context.label_id++;
}

// Parse 'sys' parameter into fp_context.cur_sys[].
void config_parse_sys(char *val) {

	if (fp_context.cur_sys) {
		fp_context.cur_sys     = nullptr;
		fp_context.cur_sys_cnt = 0;
	}

	while (*val) {

		bool is_cl = false;

		while (isblank(*val) || *val == ',') {
			val++;
		}

		if (*val == '@') {
			is_cl = true;
			val++;
		}

		char *nxt = val;

		while (isalnum(*nxt) || (*nxt && strchr(NAME_CHARS, *nxt))) {
			nxt++;
		}

		if (nxt == val || (*nxt && *nxt != ',')) {
			FATAL("Malformed sys entry in line %u.", fp_context.line_no);
		}

		char orig = *nxt;
		*nxt      = 0;

		uint32_t i;
		if (is_cl) {

			auto it = std::find_if(fp_context.fp_os_classes.begin(), fp_context.fp_os_classes.end(), [val](const std::string &os_class) {
				return strcasecmp(val, os_class.c_str()) == 0;
			});

			if (it == fp_context.fp_os_classes.end())
				FATAL("Unknown class '%s' in line %u.", val, fp_context.line_no);

			i = std::distance(fp_context.fp_os_classes.begin(), it) | SYS_CLASS_FLAG;

		} else {

			for (i = 0; i < fp_context.fp_os_names.size(); i++) {
				if (!strcasecmp(val, fp_context.fp_os_names[i])) {
					break;
				}
			}

			if (i == fp_context.fp_os_names.size()) {
				fp_context.fp_os_names.push_back(ck_memdup_str(val, nxt - val));
			}
		}

		fp_context.cur_sys                           = static_cast<uint32_t *>(realloc(fp_context.cur_sys, (fp_context.cur_sys_cnt + 1) * 4));
		fp_context.cur_sys[fp_context.cur_sys_cnt++] = i;

		*nxt = orig;
		val  = nxt;
	}
}

// Read p0f.fp line, dispatching it to fingerprinting modules as necessary.
void config_parse_line(char *line) {

	char *val = nullptr;
	char *eon = nullptr;

	// Special handling for [module:direction]...
	if (*line == '[') {

		char *dir = nullptr;

		line++;

		// Simplified case for [mtu].
		if (!strcmp(line, "mtu]")) {

			fp_context.mod_type = CF_MOD_MTU;
			fp_context.state    = CF_NEED_LABEL;
			return;
		}

		dir = strchr(line, ':');

		if (!dir)
			FATAL("Malformed section identifier in line %u.", fp_context.line_no);

		*dir = 0;
		dir++;

		if (!strcmp(line, "tcp")) {

			fp_context.mod_type = CF_MOD_TCP;

		} else if (!strcmp(line, "http")) {

			fp_context.mod_type = CF_MOD_HTTP;

		} else {

			FATAL("Unrecognized fingerprinting module '%s' in line %u.", line, fp_context.line_no);
		}

		if (!strcmp(dir, "request]")) {

			fp_context.mod_to_srv = 1;

		} else if (!strcmp(dir, "response]")) {

			fp_context.mod_to_srv = 0;

		} else {

			FATAL("Unrecognized traffic direction in line %u.", fp_context.line_no);
		}

		fp_context.state = CF_NEED_LABEL;
		return;
	}

	// Everything else follows the 'name = value' approach.
	val = line;

	while (isalpha(*val) || *val == '_')
		val++;
	eon = val;

	while (isblank(*val))
		val++;

	if (line == val || *val != '=')
		FATAL("Unexpected statement in line %u.", fp_context.line_no);

	while (isblank(*++val))
		;

	*eon = 0;

	if (!strcmp(line, "classes")) {

		if (fp_context.state != CF_NEED_SECT)
			FATAL("misplaced 'classes' in line %u.", fp_context.line_no);

		config_parse_classes(val);

	} else if (!strcmp(line, "ua_os")) {

		if (fp_context.state != CF_NEED_LABEL || fp_context.mod_to_srv != 1 || fp_context.mod_type != CF_MOD_HTTP)
			FATAL("misplaced 'us_os' in line %u.", fp_context.line_no);

		http_parse_ua(val, fp_context.line_no);

	} else if (!strcmp(line, "label")) {

		/* We will drop sig_sys / fp_context.sig_flavor on the floor if no signatures
	   actually created, but it's not worth tracking that. */

		if (fp_context.state != CF_NEED_LABEL && fp_context.state != CF_NEED_SIG)
			FATAL("misplaced 'label' in line %u.", fp_context.line_no);

		config_parse_label(val);

		if (fp_context.mod_type != CF_MOD_MTU && fp_context.sig_class < 0)
			fp_context.state = CF_NEED_SYS;
		else
			fp_context.state = CF_NEED_SIG;

	} else if (!strcmp(line, "sys")) {

		if (fp_context.state != CF_NEED_SYS)
			FATAL("Misplaced 'sys' in line %u.", fp_context.line_no);

		config_parse_sys(val);

		fp_context.state = CF_NEED_SIG;

	} else if (!strcmp(line, "sig")) {

		if (fp_context.state != CF_NEED_SIG) FATAL("Misplaced 'sig' in line %u.", fp_context.line_no);

		switch (fp_context.mod_type) {

		case CF_MOD_TCP:
			tcp_register_sig(fp_context.mod_to_srv, fp_context.generic, fp_context.sig_class, fp_context.sig_name, fp_context.sig_flavor,
							 fp_context.label_id, fp_context.cur_sys, fp_context.cur_sys_cnt, val, fp_context.line_no);
			break;

		case CF_MOD_MTU:
			mtu_register_sig(fp_context.sig_flavor, val, fp_context.line_no);
			break;

		case CF_MOD_HTTP:
			http_register_sig(fp_context.mod_to_srv, fp_context.generic, fp_context.sig_class, fp_context.sig_name, fp_context.sig_flavor,
							  fp_context.label_id, fp_context.cur_sys, fp_context.cur_sys_cnt, val, fp_context.line_no);
			break;
		}

		fp_context.sig_cnt++;

	} else {

		FATAL("Unrecognized field '%s' in line %u.", line, fp_context.line_no);
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
