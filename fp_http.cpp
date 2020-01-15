/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_FP_HTTP
//#define _GNU_SOURCE

#include <ctype.h>
#include <ostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/types.h>

#include "alloc-inl.h"
#include "config.h"
#include "debug.h"
#include "hash.h"
#include "p0f.h"
#include "process.h"
#include "readfp.h"
#include "tcp.h"
#include "types.h"

#include "fp_http.h"
#include "languages.h"

#define SLOF(_str) _str, strlen(_str)

namespace {

struct header_name {
	size_t size;
	char *name;
};

struct http_context_t {
	struct http_id req_optional[sizeof(req_optional_init) / sizeof(http_id)];
	struct http_id resp_optional[sizeof(resp_optional_init) / sizeof(http_id)];
	struct http_id req_common[sizeof(req_common_init) / sizeof(http_id)];
	struct http_id resp_common[sizeof(resp_common_init) / sizeof(http_id)];
	struct http_id req_skipval[sizeof(req_skipval_init) / sizeof(http_id)];
	struct http_id resp_skipval[sizeof(resp_skipval_init) / sizeof(http_id)];

	struct header_name *hdr_names; // List of header names by ID
	uint32_t hdr_cnt;              // Number of headers registered

	uint32_t *hdr_by_hash[SIG_BUCKETS]; // Hashed header names
	uint32_t hbh_cnt[SIG_BUCKETS];      // Number of headers in bucket

	/* Signatures aren't bucketed due to the complex matching used; but we use
	 * Bloom filters to go through them quickly. */
	struct http_sig_record *sigs[2];
	uint32_t sig_cnt[2];

	struct ua_map_record *ua_map; // Mappings between U-A and OS
	uint32_t ua_map_cnt;
};

http_context_t http_context;

/* Ghetto Bloom filter 4-out-of-64 bitmask generator for adding 32-bit header
 * IDs to a set. We expect around 10 members in a set. */
constexpr uint64_t bloom4_64(uint32_t val) {
	const uint32_t hash = hash32(&val, 4);
	uint64_t ret        = (1ULL << (hash & 63));
	ret ^= (1ULL << ((hash >> 8) & 63));
	ret ^= (1ULL << ((hash >> 16) & 63));
	ret ^= (1ULL << ((hash >> 24) & 63));
	return ret;
}

// Look up or register new header
int32_t lookup_hdr(const char *name, size_t len, uint8_t create) {

	uint32_t bucket = hash32(name, len) % SIG_BUCKETS;

	uint32_t *p = http_context.hdr_by_hash[bucket];
	uint32_t i  = http_context.hbh_cnt[bucket];

	while (i--) {
		if (http_context.hdr_names[*p].size == len && !memcmp(http_context.hdr_names[*p].name, name, len) && !http_context.hdr_names[*p].name[len])
			return *p;
		p++;
	}

	// Not found!
	if (!create)
		return -1;

	http_context.hdr_names = static_cast<struct header_name *>(realloc(http_context.hdr_names, (http_context.hdr_cnt + 1) * sizeof(struct header_name)));

	http_context.hdr_names[http_context.hdr_cnt].name = ck_memdup_str(name, len);
	http_context.hdr_names[http_context.hdr_cnt].size = len;

	http_context.hdr_by_hash[bucket] = static_cast<uint32_t *>(realloc(http_context.hdr_by_hash[bucket], (http_context.hbh_cnt[bucket] + 1) * 4));

	http_context.hdr_by_hash[bucket][http_context.hbh_cnt[bucket]++] = http_context.hdr_cnt++;

	return http_context.hdr_cnt - 1;
}

}

// Pre-register essential headers.

void http_init() {

	memcpy(&http_context.req_optional, &req_optional_init, sizeof(http_context.req_optional));
	memcpy(&http_context.resp_optional, &resp_optional_init, sizeof(http_context.resp_optional));
	memcpy(&http_context.req_common, &req_common_init, sizeof(http_context.req_common));
	memcpy(&http_context.resp_common, &resp_common_init, sizeof(http_context.resp_common));
	memcpy(&http_context.req_skipval, &req_skipval_init, sizeof(http_context.req_skipval));
	memcpy(&http_context.resp_skipval, &resp_skipval_init, sizeof(http_context.resp_skipval));

	uint32_t i;

	// Do not change - other code depends on the ordering of first 6 entries.
	lookup_hdr(SLOF("User-Agent"), 1);      // 0
	lookup_hdr(SLOF("Server"), 1);          // 1
	lookup_hdr(SLOF("Accept-Language"), 1); // 2
	lookup_hdr(SLOF("Via"), 1);             // 3
	lookup_hdr(SLOF("X-Forwarded-For"), 1); // 4
	lookup_hdr(SLOF("Date"), 1);            // 5

#define HDR_UA 0
#define HDR_SRV 1
#define HDR_AL 2
#define HDR_VIA 3
#define HDR_XFF 4
#define HDR_DAT 5

	i = 0;
	while (http_context.req_optional[i].name) {
		http_context.req_optional[i].id = lookup_hdr(SLOF(http_context.req_optional[i].name), 1);
		i++;
	}

	i = 0;
	while (http_context.resp_optional[i].name) {
		http_context.resp_optional[i].id = lookup_hdr(SLOF(http_context.resp_optional[i].name), 1);
		i++;
	}

	i = 0;
	while (http_context.req_skipval[i].name) {
		http_context.req_skipval[i].id = lookup_hdr(SLOF(http_context.req_skipval[i].name), 1);
		i++;
	}

	i = 0;
	while (http_context.resp_skipval[i].name) {
		http_context.resp_skipval[i].id = lookup_hdr(SLOF(http_context.resp_skipval[i].name), 1);
		i++;
	}

	i = 0;
	while (http_context.req_common[i].name) {
		http_context.req_common[i].id = lookup_hdr(SLOF(http_context.req_common[i].name), 1);
		i++;
	}

	i = 0;
	while (http_context.resp_common[i].name) {
		http_context.resp_common[i].id = lookup_hdr(SLOF(http_context.resp_common[i].name), 1);
		i++;
	}
}

// Find match for a signature.

static void http_find_match(uint8_t to_srv, struct http_sig *ts, uint8_t dupe_det) {

	struct http_sig_record *gmatch = nullptr;
	struct http_sig_record *ref    = http_context.sigs[to_srv];
	uint32_t cnt                   = http_context.sig_cnt[to_srv];

	while (cnt--) {

		struct http_sig *rs = ref->sig;
		uint32_t ts_hdr = 0, rs_hdr = 0;

		if (rs->http_ver != -1 && rs->http_ver != ts->http_ver) goto next_sig;

		/* Check that all the headers listed for the p0f.fp signature (probably)
		 * appear in the examined traffic. */

		if ((ts->hdr_bloom4 & rs->hdr_bloom4) != rs->hdr_bloom4) goto next_sig;

		/* Confirm the ordering and values of headers (this is relatively slow,
		 * hence the Bloom filter first). */

		while (rs_hdr < rs->hdr_cnt) {

			uint32_t orig_ts = ts_hdr;

			while (ts_hdr < ts->hdr_cnt && rs->hdr[rs_hdr].id != ts->hdr[ts_hdr].id) {
				ts_hdr++;
			}

			if (ts_hdr == ts->hdr_cnt) {

				if (!rs->hdr[rs_hdr].optional) goto next_sig;

				/* If this is an optional header, check that it doesn't appear
				 * anywhere else. */

				for (ts_hdr = 0; ts_hdr < ts->hdr_cnt; ts_hdr++)
					if (rs->hdr[rs_hdr].id == ts->hdr[ts_hdr].id) goto next_sig;

				ts_hdr = orig_ts;
				rs_hdr++;
				continue;
			}

			if (rs->hdr[rs_hdr].value && (!ts->hdr[ts_hdr].value || !strstr(ts->hdr[ts_hdr].value, rs->hdr[rs_hdr].value)))
				goto next_sig;

			ts_hdr++;
			rs_hdr++;
		}

		/* Check that the headers forbidden in p0f.fp don't appear in the traffic.
		 * We first check if they seem to appear in ts->hdr_bloom4, and only if so,
		 * we do a full check. */
		for (rs_hdr = 0; rs_hdr < rs->miss_cnt; rs_hdr++) {

			uint64_t miss_bloom4 = bloom4_64(rs->miss[rs_hdr]);

			if ((ts->hdr_bloom4 & miss_bloom4) != miss_bloom4)
				continue;

			// Okay, possible instance of a banned header - scan list...
			for (ts_hdr = 0; ts_hdr < ts->hdr_cnt; ts_hdr++)
				if (rs->miss[rs_hdr] == ts->hdr[ts_hdr].id)
					goto next_sig;
		}

		/* When doing dupe detection, we want to allow a signature with
		 * additional banned headers to precede one with fewer,
		 * or with a different set. */

		if (dupe_det) {

			if (rs->miss_cnt > ts->miss_cnt)
				goto next_sig;

			for (rs_hdr = 0; rs_hdr < rs->miss_cnt; rs_hdr++) {

				for (ts_hdr = 0; ts_hdr < ts->miss_cnt; ts_hdr++)
					if (rs->miss[rs_hdr] == ts->miss[ts_hdr])
						break;

				// One of the reference headers doesn't appear in current sig!

				if (ts_hdr == ts->miss_cnt)
					goto next_sig;
			}
		}

		// Whoa, a match.
		if (!ref->generic) {
			ts->matched = ref;

			if (rs->sw && ts->sw && !strstr(ts->sw, rs->sw)) {
				ts->dishonest = 1;
			}

			return;

		} else if (!gmatch)
			gmatch = ref;

	next_sig:
		ref = ref + 1;
	}

	// A generic signature is the best we could find.

	if (!dupe_det && gmatch) {
		ts->matched = gmatch;
		if (gmatch->sig->sw && ts->sw && !strstr(ts->sw, gmatch->sig->sw))
			ts->dishonest = 1;
	}
}

// Register new HTTP signature.

void http_register_sig(uint8_t to_srv, uint8_t generic, int32_t sig_class, uint32_t sig_name, char *sig_flavor, uint32_t label_id, uint32_t *sys, uint32_t sys_cnt, char *val, uint32_t line_no) {

	char *nxt;

	auto hsig = static_cast<struct http_sig *>(calloc(sizeof(struct http_sig), 1));

	http_context.sigs[to_srv] = static_cast<struct http_sig_record *>(realloc(http_context.sigs[to_srv], sizeof(struct http_sig_record) * (http_context.sig_cnt[to_srv] + 1)));

	struct http_sig_record *hrec = &http_context.sigs[to_srv][http_context.sig_cnt[to_srv]];

	if (val[1] != ':')
		FATAL("Malformed signature in line %u.", line_no);

	// http_ver
	switch (*val) {
	case '0':
		break;
	case '1':
		hsig->http_ver = 1;
		break;
	case '*':
		hsig->http_ver = -1;
		break;
	default:
		FATAL("Bad HTTP version in line %u.", line_no);
	}

	val += 2;

	// horder

	while (*val != ':') {

		uint8_t optional = 0;

		if (hsig->hdr_cnt >= HTTP_MAX_HDRS)
			FATAL("Too many headers listed in line %u.", line_no);

		nxt = val;

		if (*nxt == '?') {
			optional = 1;
			val++;
			nxt++;
		}

		while (isalnum(*nxt) || *nxt == '-' || *nxt == '_')
			nxt++;

		if (val == nxt)
			FATAL("Malformed header name in line %u.", line_no);

		uint32_t id = lookup_hdr(val, nxt - val, 1);

		hsig->hdr[hsig->hdr_cnt].id       = id;
		hsig->hdr[hsig->hdr_cnt].optional = optional;

		if (!optional)
			hsig->hdr_bloom4 |= bloom4_64(id);

		val = nxt;

		if (*val == '=') {

			if (val[1] != '[')
				FATAL("Missing '[' after '=' in line %u.", line_no);

			val += 2;
			nxt = val;

			while (*nxt && *nxt != ']')
				nxt++;

			if (val == nxt || !*nxt)
				FATAL("Malformed signature in line %u.", line_no);

			hsig->hdr[hsig->hdr_cnt].value = ck_memdup_str(val, nxt - val);

			val = nxt + 1;
		}

		hsig->hdr_cnt++;

		if (*val == ',')
			val++;
		else if (*val != ':')
			FATAL("Malformed signature in line %u.", line_no);
	}

	val++;

	// habsent

	while (*val != ':') {

		if (hsig->miss_cnt >= HTTP_MAX_HDRS)
			FATAL("Too many headers listed in line %u.", line_no);

		nxt = val;
		while (isalnum(*nxt) || *nxt == '-' || *nxt == '_')
			nxt++;

		if (val == nxt)
			FATAL("Malformed header name in line %u.", line_no);

		uint32_t id = lookup_hdr(val, nxt - val, 1);

		hsig->miss[hsig->miss_cnt] = id;

		val = nxt;

		hsig->miss_cnt++;

		if (*val == ',')
			val++;
		else if (*val != ':')
			FATAL("Malformed signature in line %u.", line_no);
	}

	val++;

	// exp_sw

	if (*val) {

		if (strchr(val, ':'))
			FATAL("Malformed signature in line %u.", line_no);

		hsig->sw = ck_strdup(val);
	}

	http_find_match(to_srv, hsig, 1);

	if (hsig->matched)
		FATAL("Signature in line %u is already covered by line %u.",
			  line_no, hsig->matched->line_no);

	hrec->class_id = sig_class;
	hrec->name_id  = sig_name;
	hrec->flavor   = sig_flavor;
	hrec->label_id = label_id;
	hrec->sys      = sys;
	hrec->sys_cnt  = sys_cnt;
	hrec->line_no  = line_no;
	hrec->generic  = generic;

	hrec->sig = hsig;

	http_context.sig_cnt[to_srv]++;
}

// Register new HTTP signature.

void http_parse_ua(char *val, uint32_t line_no) {

	char *nxt;

	while (*val) {

		uint32_t id;
		char *name = nullptr;

		nxt = val;
		while (*nxt && (isalnum(*nxt) || strchr(NAME_CHARS, *nxt)))
			nxt++;

		if (val == nxt)
			FATAL("Malformed system name in line %u.", line_no);

		id = lookup_name_id(val, nxt - val);

		val = nxt;

		if (*val == '=') {

			if (val[1] != '[')
				FATAL("Missing '[' after '=' in line %u.", line_no);

			val += 2;
			nxt = val;

			while (*nxt && *nxt != ']')
				nxt++;

			if (val == nxt || !*nxt)
				FATAL("Malformed signature in line %u.", line_no);

			name = ck_memdup_str(val, nxt - val);

			val = nxt + 1;
		}

		http_context.ua_map = static_cast<struct ua_map_record *>(realloc(http_context.ua_map, (http_context.ua_map_cnt + 1) * sizeof(struct ua_map_record)));

		http_context.ua_map[http_context.ua_map_cnt].id = id;

		if (!name)
			http_context.ua_map[http_context.ua_map_cnt].name = fp_os_names[id];
		else
			http_context.ua_map[http_context.ua_map_cnt].name = name;

		http_context.ua_map_cnt++;

		if (*val == ',') val++;
	}
}

// Dump a HTTP signature.
static const char *dump_sig(uint8_t to_srv, const struct http_sig *hsig) {

	uint32_t i;
	uint8_t had_prev = 0;
	struct http_id *list;

	uint8_t tmp[HTTP_MAX_SHOW + 1];
	uint32_t tpos;

	std::stringstream ss;
	char *val;

	append_format(ss, "%u:", hsig->http_ver);

	for (i = 0; i < hsig->hdr_cnt; i++) {

		if (hsig->hdr[i].id >= 0) {

			uint8_t optional = 0;

			// Check the "optional" list.

			list = to_srv ? http_context.req_optional : http_context.resp_optional;

			while (list->name) {
				if (list->id == hsig->hdr[i].id) break;
				list++;
			}

			if (list->name) optional = 1;

			append_format(ss, "%s%s%s", had_prev ? "," : "", optional ? "?" : "", http_context.hdr_names[hsig->hdr[i].id].name);
			had_prev = 1;

			if (!(val = hsig->hdr[i].value)) continue;

			// Next, make sure that the value is not on the ignore list.

			if (optional) continue;

			list = to_srv ? http_context.req_skipval : http_context.resp_skipval;

			while (list->name) {
				if (list->id == hsig->hdr[i].id) break;
				list++;
			}

			if (list->name) continue;

			/* Looks like it's not on the list, so let's output a cleaned-up version
         up to HTTP_MAX_SHOW. */

			tpos = 0;

			while (tpos < HTTP_MAX_SHOW && val[tpos] >= 0x20 && static_cast<uint8_t>(val[tpos]) < 0x80 &&
				   val[tpos] != ']' && val[tpos] != '|') {

				tmp[tpos] = val[tpos];
				tpos++;
			}

			tmp[tpos] = 0;

			if (!tpos) continue;

			append_format(ss, "=[%s]", tmp);

		} else {

			append_format(ss, "%s%s", had_prev ? "," : "", hsig->hdr[i].name);
			had_prev = 1;

			if (!(val = hsig->hdr[i].value))
				continue;

			tpos = 0;

			while (tpos < HTTP_MAX_SHOW && val[tpos] >= 0x20 && static_cast<uint8_t>(val[tpos]) < 0x80 && val[tpos] != ']') {
				tmp[tpos] = val[tpos];
				tpos++;
			}

			tmp[tpos] = 0;

			if (!tpos) continue;

			append_format(ss, "=[%s]", tmp);
		}
	}

	append_format(ss, ":");

	list     = to_srv ? http_context.req_common : http_context.resp_common;
	had_prev = 0;

	while (list->name) {

		for (i = 0; i < hsig->hdr_cnt; i++)
			if (hsig->hdr[i].id == list->id)
				break;

		if (i == hsig->hdr_cnt) {
			append_format(ss, "%s%s", had_prev ? "," : "", list->name);
			had_prev = 1;
		}

		list++;
	}

	append_format(ss, ":");

	if ((val = hsig->sw)) {

		tpos = 0;

		while (tpos < HTTP_MAX_SHOW && val[tpos] >= 0x20 && static_cast<uint8_t>(val[tpos]) < 0x80 && val[tpos] != ']') {

			tmp[tpos] = val[tpos];
			tpos++;
		}

		tmp[tpos] = 0;

		if (tpos) append_format(ss, "%s", tmp);
	}

	static std::string ret;
	ret = ss.str();

	return ret.c_str();
}

// Dump signature flags.

static const char *dump_flags(const struct http_sig *hsig, const struct http_sig_record *m) {

	std::stringstream ss;

	if (hsig->dishonest) append_format(ss, " dishonest");
	if (!hsig->sw) append_format(ss, " anonymous");
	if (m && m->generic) append_format(ss, " generic");

	static std::string ret;
	ret = ss.str();

	if (!ret.empty()) {
		return ret.c_str() + 1;
	} else {
		return "none";
	}
}

/* Score signature differences. For unknown signatures, the presumption is that
   they identify apps, so the logic is quite different from TCP. */

static void score_nat(uint8_t to_srv, const struct packet_flow *f) {

	struct http_sig_record *m = f->http_tmp.matched;
	struct host_data *hd;
	struct http_sig *ref;

	uint8_t score = 0, diff_already = 0;
	uint16_t reason = 0;

	if (to_srv) {

		hd  = f->client;
		ref = hd->http_req_os;

	} else {

		hd  = f->server;
		ref = hd->http_resp;

		// If the signature is for a different port, don't read too much into it.

		if (hd->http_resp_port != f->srv_port) ref = nullptr;
	}

	if (!m) {

		/* No match. The user is probably running another app; this is only of
       interest if a server progresses from known to unknown. We can't
       compare two unknown server sigs with that much confidence. */

		if (!to_srv && ref && ref->matched) {

			DEBUG("[#] HTTP server signature changed from known to unknown.\n");
			score += 4;
			reason |= NAT_TO_UNK;
		}

		goto header_check;
	}

	if (m->class_id == -1) {

		/* Got a match for an application signature. Make sure it runs on the
       OS we have on file... */

		verify_tool_class(to_srv, f, m->sys, m->sys_cnt);

		// ...and check for inconsistencies in server behavior.

		if (!to_srv && ref && ref->matched) {

			if (ref->matched->name_id != m->name_id) {

				DEBUG("[#] Name on the matched HTTP server signature changes.\n");
				score += 8;
				reason |= NAT_APP_LB;

			} else if (ref->matched->label_id != m->label_id) {

				DEBUG("[#] Label on the matched HTTP server signature changes.\n");
				score += 2;
				reason |= NAT_APP_LB;
			}
		}

	} else {

		/* Ooh, spiffy: a match for an OS signature! There will be about two uses
       for this code, ever. */

		if (ref && ref->matched) {

			if (ref->matched->name_id != m->name_id) {

				DEBUG("[#] Name on the matched HTTP OS signature changes.\n");
				score += 8;
				reason |= NAT_OS_SIG;
				diff_already = 1;

			} else if (ref->matched->name_id != m->label_id) {

				DEBUG("[#] Label on the matched HTTP OS signature changes.\n");
				score += 2;
				reason |= NAT_OS_SIG;
			}

		} else if (ref) {

			DEBUG("[#] HTTP OS signature changed from unknown to known.\n");
			score += 4;
			reason |= NAT_TO_UNK;
		}

		/* If we haven't pointed out anything major yet, also complain if the
       signature doesn't match host data. */

		if (!diff_already && hd->last_name_id != m->name_id) {

			DEBUG("[#] Matched HTTP OS signature different than host data.\n");
			score += 4;
			reason |= NAT_OS_SIG;
		}
	}

	/* If we have determined that U-A looks legit, but the OS doesn't match,
     that's a clear sign of trouble. */

	if (to_srv && m->class_id == -1 && f->http_tmp.sw && !f->http_tmp.dishonest) {

		uint32_t i;

		for (i = 0; i < http_context.ua_map_cnt; i++)
			if (strstr(f->http_tmp.sw, http_context.ua_map[i].name)) break;

		if (i != http_context.ua_map_cnt) {

			if (http_context.ua_map[i].id != hd->last_name_id) {

				DEBUG("[#] Otherwise plausible User-Agent points to another OS.\n");
				score += 4;
				reason |= NAT_APP_UA;

				if (!hd->bad_sw) hd->bad_sw = 1;

			} else {

				DEBUG("[#] User-Agent OS value checks out.\n");
				hd->bad_sw = 0;
			}
		}
	}

header_check:

	// Okay, some last-resort checks. This is obviously concerning:

	if (f->http_tmp.via) {
		DEBUG("[#] Explicit use of Via or X-Forwarded-For.\n");
		score += 8;
		reason |= NAT_APP_VIA;
	}

	// Last but not least, see what happened to 'Date':

	if (ref && !to_srv && ref->date && f->http_tmp.date) {

		auto recv_diff = static_cast<int64_t>(f->http_tmp.recv_date) - ref->recv_date;
		auto hdr_diff  = static_cast<int64_t>(f->http_tmp.date) - ref->date;

		if (hdr_diff < -HTTP_MAX_DATE_DIFF ||
			hdr_diff > recv_diff + HTTP_MAX_DATE_DIFF) {

			DEBUG("[#] HTTP 'Date' distance too high (%ld in %ld sec).\n",
				  hdr_diff, recv_diff);
			score += 4;
			reason |= NAT_APP_DATE;

		} else {

			DEBUG("[#] HTTP 'Date' distance seems fine (%ld in %ld sec).\n",
				  hdr_diff, recv_diff);
		}
	}

	add_nat_score(to_srv, f, reason, score);
}

// Look up HTTP signature, create an observation.

static void fingerprint_http(uint8_t to_srv, struct packet_flow *f) {

	struct http_sig_record *m;
	const char *lang = nullptr;

	http_find_match(to_srv, &f->http_tmp, 0);

	start_observation(to_srv ? "http request" : "http response", 4, to_srv, f);

	if ((m = f->http_tmp.matched)) {

		observf((m->class_id < 0) ? "app" : "os", "%s%s%s",
				fp_os_names[m->name_id], m->flavor ? " " : "",
				m->flavor ? m->flavor : "");

	} else
		add_observation_field("app", nullptr);

	if (f->http_tmp.lang && isalpha(f->http_tmp.lang[0]) &&
		isalpha(f->http_tmp.lang[1]) && !isalpha(f->http_tmp.lang[2])) {

		uint8_t lh  = LANG_HASH(f->http_tmp.lang[0], f->http_tmp.lang[1]);
		uint8_t pos = 0;

		while (languages[lh][pos]) {
			if (f->http_tmp.lang[0] == languages[lh][pos][0] &&
				f->http_tmp.lang[1] == languages[lh][pos][1]) break;
			pos += 2;
		}

		if (!languages[lh][pos])
			add_observation_field("lang", nullptr);
		else
			add_observation_field("lang",
								  (lang = languages[lh][pos + 1]));

	} else
		add_observation_field("lang", "none");

	add_observation_field("params", dump_flags(&f->http_tmp, m));

	add_observation_field("raw_sig", dump_sig(to_srv, &f->http_tmp));

	score_nat(to_srv, f);

	// Save observations needed to score future responses.

	if (!to_srv) {

		// For server response, always store the signature.

		free(f->server->http_resp);
		f->server->http_resp = static_cast<struct http_sig *>(ck_memdup(&f->http_tmp, sizeof(struct http_sig)));

		f->server->http_resp->hdr_cnt = 0;
		f->server->http_resp->sw      = nullptr;
		f->server->http_resp->lang    = nullptr;
		f->server->http_resp->via     = nullptr;

		f->server->http_resp_port = f->srv_port;

		if (lang) f->server->language = lang;

		if (m) {

			if (m->class_id != -1) {

				// If this is an OS signature, update host record.

				f->server->last_class_id = m->class_id;
				f->server->last_name_id  = m->name_id;
				f->server->last_flavor   = m->flavor;
				f->server->last_quality  = (m->generic * P0F_MATCH_GENERIC);

			} else {

				// Otherwise, record app data.

				f->server->http_name_id = m->name_id;
				f->server->http_flavor  = m->flavor;

				if (f->http_tmp.dishonest) f->server->bad_sw = 2;
			}
		}

	} else {

		if (lang) f->client->language = lang;

		if (m) {

			if (m->class_id != -1) {

				// Client request - only OS sig is of any note.

				free(f->client->http_req_os);
				f->client->http_req_os = static_cast<struct http_sig *>(ck_memdup(&f->http_tmp, sizeof(struct http_sig)));

				f->client->http_req_os->hdr_cnt = 0;
				f->client->http_req_os->sw      = nullptr;
				f->client->http_req_os->lang    = nullptr;
				f->client->http_req_os->via     = nullptr;

				f->client->last_class_id = m->class_id;
				f->client->last_name_id  = m->name_id;
				f->client->last_flavor   = m->flavor;

				f->client->last_quality = (m->generic * P0F_MATCH_GENERIC);

			} else {

				// Record app data for the API.

				f->client->http_name_id = m->name_id;
				f->client->http_flavor  = m->flavor;

				if (f->http_tmp.dishonest) f->client->bad_sw = 2;
			}
		}
	}
}

// Free up any allocated strings in http_sig.

void free_sig_hdrs(struct http_sig *h) {

	uint32_t i;

	for (i = 0; i < h->hdr_cnt; i++) {
		if (h->hdr[i].name) free(h->hdr[i].name);
		if (h->hdr[i].value) free(h->hdr[i].value);
	}
}

// Parse HTTP date field.

static time_t parse_date(const char *str) {
	struct tm t;

	if (!strptime(str, "%a, %d %b %Y %H:%M:%S %Z", &t)) {
		DEBUG("[#] Invalid 'Date' field ('%s').\n", str);
		return 0;
	}

	return mktime(&t);
}

// Parse name=value pairs into a signature.

static uint8_t parse_pairs(uint8_t to_srv, struct packet_flow *f, uint8_t can_get_more) {

	uint32_t plen = to_srv ? f->req_len : f->resp_len;

	uint32_t off;

	// Try to parse name: value pairs.

	while ((off = f->http_pos) < plen) {

		char *pay = to_srv ? f->request : f->response;

		uint32_t nlen, vlen, vstart;
		uint32_t hcount;

		// Empty line? Dispatch for fingerprinting!

		if (pay[off] == '\r' || pay[off] == '\n') {

			f->http_tmp.recv_date = get_unix_time();

			fingerprint_http(to_srv, f);

			/* If this is a request, flush the collected signature and prepare
         for parsing the response. If it's a response, just shut down HTTP
         parsing on this flow. */

			if (to_srv) {

				f->http_req_done = 1;
				f->http_pos      = 0;

				free_sig_hdrs(&f->http_tmp);
				memset(&f->http_tmp, 0, sizeof(struct http_sig));

				return 1;

			} else {

				f->in_http = -1;
				return 0;
			}
		}

		// Looks like we're getting a header value. See if we have room for it.

		if ((hcount = f->http_tmp.hdr_cnt) >= HTTP_MAX_HDRS) {

			DEBUG("[#] Too many HTTP headers in a %s.\n", to_srv ? "request" : "response");

			f->in_http = -1;
			return 0;
		}

		// Try to extract header name.

		nlen = 0;

		while ((isalnum(pay[off]) || pay[off] == '-' || pay[off] == '_') &&
			   off < plen && nlen <= HTTP_MAX_HDR_NAME) {

			off++;
			nlen++;
		}

		if (off == plen) {

			if (!can_get_more) {

				DEBUG("[#] End of HTTP %s before end of headers.\n",
					  to_srv ? "request" : "response");
				f->in_http = -1;
			}

			return can_get_more;
		}

		// Empty, excessively long, or non-':'-followed header name?

		if (!nlen || pay[off] != ':' || nlen > HTTP_MAX_HDR_NAME) {

			DEBUG("[#] Invalid HTTP header encountered (len = %u, char = 0x%02x).\n",
				  nlen, pay[off]);

			f->in_http = -1;
			return 0;
		}

		/* At this point, header name starts at f->http_pos, and has nlen bytes.
       Skip ':' and a subsequent whitespace next. */

		off++;

		if (off < plen && isblank(pay[off])) off++;

		vstart = off;
		vlen   = 0;

		// Find the next \n.

		while (off < plen && vlen <= HTTP_MAX_HDR_VAL && pay[off] != '\n') {

			off++;
			vlen++;
		}

		if (vlen > HTTP_MAX_HDR_VAL) {
			DEBUG("[#] HTTP %s header value length exceeded.\n",
				  to_srv ? "request" : "response");
			f->in_http = -1;
			return -1;
		}

		if (off == plen) {

			if (!can_get_more) {
				DEBUG("[#] End of HTTP %s before end of headers.\n",
					  to_srv ? "request" : "response");
				f->in_http = -1;
			}

			return can_get_more;
		}

		// If party is using \r\n terminators, go back one char.

		if (pay[off - 1] == '\r') vlen--;

		/* Header value starts at vstart, and has vlen bytes (may be zero).
		 * Record this in the signature. */

		const int32_t hid = lookup_hdr(pay + f->http_pos, nlen, 0);

		f->http_tmp.hdr[hcount].id = hid;

		if (hid < 0) {
			// Header ID not found, store literal value.
			f->http_tmp.hdr[hcount].name = ck_memdup_str(pay + f->http_pos, nlen);
		} else {
			// Found - update Bloom filter.
			f->http_tmp.hdr_bloom4 |= bloom4_64(hid);
		}

		/* If there's a value, store that too. For U-A and Server, also update
       'sw'; and for requests, collect Accept-Language. */

		if (vlen) {

			auto val = ck_memdup_str(pay + vstart, vlen);

			f->http_tmp.hdr[hcount].value = val;

			if (to_srv) {
				switch (hid) {
				case HDR_UA:
					f->http_tmp.sw = val;
					break;
				case HDR_AL:
					f->http_tmp.lang = val;
					break;
				case HDR_VIA:
				case HDR_XFF:
					f->http_tmp.via = val;
					break;
				}

			} else {
				switch (hid) {
				case HDR_SRV:
					f->http_tmp.sw = val;
					break;
				case HDR_DAT:
					f->http_tmp.date = parse_date(val);
					break;
				case HDR_VIA:
				case HDR_XFF:
					f->http_tmp.via = val;
					break;
				}
			}
		}

		// Moving on...

		f->http_tmp.hdr_cnt++;
		f->http_pos = off + 1;
	}

	if (!can_get_more) {
		DEBUG("[#] End of HTTP %s before end of headers.\n",
			  to_srv ? "request" : "response");
		f->in_http = -1;
	}

	return can_get_more;
}

/* Examine request or response; returns 1 if more data needed and plausibly can
   be read. Note that the buffer is always NUL-terminated. */

uint8_t process_http(uint8_t to_srv, struct packet_flow *f) {

	// Already decided this flow is not worth tracking?

	if (f->in_http < 0)
		return 0;

	if (to_srv) {

		char *pay            = f->request;
		uint8_t can_get_more = (f->req_len < MAX_FLOW_DATA);

		// Request done, but pending response?
		if (f->http_req_done)
			return 1;

		if (!f->in_http) {

			uint8_t chr;
			char *sig_at;

			// Ooh, new flow!
			if (f->req_len < 15)
				return can_get_more;

			// Scan until \n, or until binary data spotted.
			uint32_t off = f->http_pos;

			// We only care about GET and HEAD requests at this point.
			if (!off && strncmp(pay, "GET /", 5) &&
				strncmp(pay, "HEAD /", 6)) {
				DEBUG("[#] Does not seem like a GET / HEAD request.\n");
				f->in_http = -1;
				return 0;
			}

			while (off < f->req_len && off < HTTP_MAX_URL && (chr = pay[off]) != '\n') {
				if (chr != '\r' && (chr < 0x20 || chr > 0x7f)) {
					DEBUG("[#] Not HTTP - character 0x%02x encountered.\n", chr);
					f->in_http = -1;
					return 0;
				}

				off++;
			}

			// Newline too far or too close?

			if (off == HTTP_MAX_URL || off < 14) {
				DEBUG("[#] Not HTTP - newline offset %u.\n", off);
				f->in_http = -1;
				return 0;
			}

			// Not enough data yet?
			if (off == f->req_len) {
				f->http_pos = off;

				if (!can_get_more) {
					DEBUG("[#] Not HTTP - no opening line found.\n");
					f->in_http = -1;
				}

				return can_get_more;
			}

			sig_at = pay + off - 8;
			if (pay[off - 1] == '\r') sig_at--;

			// Bad HTTP/1.x signature?
			if (strncmp(sig_at, "HTTP/1.", 7)) {
				DEBUG("[#] Not HTTP - bad signature.\n");
				f->in_http = -1;
				return 0;
			}

			f->http_tmp.http_ver = (sig_at[7] == '1');

			f->in_http  = 1;
			f->http_pos = off + 1;

			DEBUG("[#] HTTP detected.\n");
		}

		return parse_pairs(1, f, can_get_more);

	} else {

		char *pay            = f->response;
		uint8_t can_get_more = (f->resp_len < MAX_FLOW_DATA);

		// Response before request? Bail out.
		if (!f->in_http || !f->http_req_done) {
			f->in_http = -1;
			return 0;
		}

		if (!f->http_gotresp1) {

			uint8_t chr;

			if (f->resp_len < 13)
				return can_get_more;

			// Scan until \n, or until binary data spotted.
			uint32_t off = f->http_pos;

			while (off < f->resp_len && off < HTTP_MAX_URL && (chr = pay[off]) != '\n') {
				if (chr != '\r' && (chr < 0x20 || chr > 0x7f)) {
					DEBUG("[#] Invalid HTTP response - character 0x%02x encountered.\n",
						  chr);
					f->in_http = -1;
					return 0;
				}

				off++;
			}

			// Newline too far or too close?
			if (off == HTTP_MAX_URL || off < 13) {
				DEBUG("[#] Invalid HTTP response - newline offset %u.\n", off);
				f->in_http = -1;
				return 0;
			}

			// Not enough data yet?
			if (off == f->resp_len) {
				f->http_pos = off;
				if (!can_get_more) {
					DEBUG("[#] Invalid HTTP response - no opening line found.\n");
					f->in_http = -1;
				}

				return can_get_more;
			}

			// Bad HTTP/1.x signature?

			if (strncmp(pay, "HTTP/1.", 7)) {
				DEBUG("[#] Invalid HTTP response - bad signature.\n");
				f->in_http = -1;
				return 0;
			}

			f->http_tmp.http_ver = (pay[7] == '1');
			f->http_pos          = off + 1;
			DEBUG("[#] HTTP response starts correctly.\n");
		}

		return parse_pairs(0, f, can_get_more);
	}
}
