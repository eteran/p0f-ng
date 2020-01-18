/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <ostream>
#include <sstream>
#include <unistd.h>
#include <vector>

#include <netinet/in.h>
#include <sys/types.h>

#include "p0f/api.h"
#include "p0f/config.h"
#include "p0f/debug.h"
#include "p0f/fp_http.h"
#include "p0f/hash.h"
#include "p0f/languages.h"
#include "p0f/p0f.h"
#include "p0f/parser.h"
#include "p0f/process.h"
#include "p0f/readfp.h"
#include "p0f/tcp.h"
#include "p0f/util.h"

http_context_t http_context;

namespace {

constexpr int HDR_UA  = 0;
constexpr int HDR_SRV = 1;
constexpr int HDR_AL  = 2;
constexpr int HDR_VIA = 3;
constexpr int HDR_XFF = 4;
constexpr int HDR_DAT = 5;

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

// Parse HTTP date field.
time_t parse_date(const char *str) {
	struct tm t = {};

	if (!strptime(str, "%a, %d %b %Y %H:%M:%S %Z", &t)) {
		DEBUG("[#] Invalid 'Date' field ('%s').\n", str);
		return 0;
	}

	return mktime(&t);
}

}

// Look up or register new header
uint32_t http_context_t::lookup_hdr(const std::string &name, bool create) {

	std::hash<std::string> hasher;
	uint32_t bucket = hasher(name) % SIG_BUCKETS;

	uint32_t *p = &hdr_by_hash_[bucket][0];
	size_t i    = hdr_by_hash_[bucket].size();

	while (i--) {
		if (hdr_names_[*p] == name) {
			return *p;
		}
		p++;
	}

	// Not found!
	if (!create)
		return InvalidId;

	const size_t index = hdr_names_.size();

	hdr_names_.push_back(name);
	hdr_by_hash_[bucket].push_back(index);

	return index;
}

// Find match for a signature.
void http_context_t::http_find_match(bool to_srv, http_sig *ts, uint8_t dupe_det) {

	http_sig_record *gmatch = nullptr;
	http_sig_record *ref    = &sigs_[to_srv][0];
	size_t cnt              = sigs_[to_srv].size();

	while (cnt--) {

		std::unique_ptr<http_sig> &rs = ref->sig;
		uint32_t ts_hdr               = 0;
		uint32_t rs_hdr               = 0;

		if (rs->http_ver != -1 && rs->http_ver != ts->http_ver)
			goto next_sig;

		/* Check that all the headers listed for the p0f.fp signature (probably)
		 * appear in the examined traffic. */
		if ((ts->hdr_bloom4 & rs->hdr_bloom4) != rs->hdr_bloom4)
			goto next_sig;

		/* Confirm the ordering and values of headers (this is relatively slow,
		 * hence the Bloom filter first). */
		while (rs_hdr < rs->hdr.size()) {

			uint32_t orig_ts = ts_hdr;

			while (ts_hdr < ts->hdr.size() && rs->hdr[rs_hdr].id != ts->hdr[ts_hdr].id) {
				ts_hdr++;
			}

			if (ts_hdr == ts->hdr.size()) {

				if (!rs->hdr[rs_hdr].optional)
					goto next_sig;

				/* If this is an optional header, check that it doesn't appear
				 * anywhere else. */
				for (ts_hdr = 0; ts_hdr < ts->hdr.size(); ts_hdr++)
					if (rs->hdr[rs_hdr].id == ts->hdr[ts_hdr].id)
						goto next_sig;

				ts_hdr = orig_ts;
				rs_hdr++;
				continue;
			}

			if (rs->hdr[rs_hdr].value && (!ts->hdr[ts_hdr].value || !strstr(ts->hdr[ts_hdr].value->c_str(), rs->hdr[rs_hdr].value->c_str())))
				goto next_sig;

			ts_hdr++;
			rs_hdr++;
		}

		/* Check that the headers forbidden in p0f.fp don't appear in the traffic.
		 * We first check if they seem to appear in ts->hdr_bloom4, and only if so,
		 * we do a full check. */
		for (rs_hdr = 0; rs_hdr < rs->miss.size(); rs_hdr++) {

			uint64_t miss_bloom4 = bloom4_64(rs->miss[rs_hdr]);

			if ((ts->hdr_bloom4 & miss_bloom4) != miss_bloom4)
				continue;

			// Okay, possible instance of a banned header - scan list...
			for (ts_hdr = 0; ts_hdr < ts->hdr.size(); ts_hdr++)
				if (rs->miss[rs_hdr] == ts->hdr[ts_hdr].id)
					goto next_sig;
		}

		/* When doing dupe detection, we want to allow a signature with
		 * additional banned headers to precede one with fewer,
		 * or with a different set. */
		if (dupe_det) {

			if (rs->miss.size() > ts->miss.size())
				goto next_sig;

			for (rs_hdr = 0; rs_hdr < rs->miss.size(); rs_hdr++) {

				for (ts_hdr = 0; ts_hdr < ts->miss.size(); ts_hdr++)
					if (rs->miss[rs_hdr] == ts->miss[ts_hdr])
						break;

				// One of the reference headers doesn't appear in current sig!
				if (ts_hdr == ts->miss.size())
					goto next_sig;
			}
		}

		// Whoa, a match.
		if (!ref->generic) {
			ts->matched = ref;

			if (rs->sw && ts->sw && !strstr(ts->sw->c_str(), rs->sw->c_str())) {
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
		if (gmatch->sig->sw && ts->sw && !strstr(ts->sw->c_str(), gmatch->sig->sw->c_str())) {
			ts->dishonest = 1;
		}
	}
}

void http_context_t::http_find_match(bool to_srv, const std::unique_ptr<http_sig> &ts, uint8_t dupe_det) {
	http_find_match(to_srv, ts.get(), dupe_det);
}

// Dump a HTTP signature.
std::string http_context_t::dump_sig(bool to_srv, const http_sig *hsig) {

	bool had_prev = false;
	http_id *list;

	std::stringstream ss;
	append_format(ss, "%u:", hsig->http_ver);

	for (size_t i = 0; i < hsig->hdr.size(); i++) {

		if (hsig->hdr[i].id != InvalidId) {

			bool optional = false;

			// Check the "optional" list.
			list = to_srv ? req_optional_ : resp_optional_;

			while (list->name) {
				if (list->id == hsig->hdr[i].id) {
					break;
				}
				list++;
			}

			if (list->name) {
				optional = true;
			}

			append_format(ss, "%s%s%s",
						  had_prev ? "," : "",
						  optional ? "?" : "",
						  hdr_names_[hsig->hdr[i].id].c_str());

			had_prev = true;

			if (hsig->hdr[i].value) {

				const char *val = hsig->hdr[i].value->c_str();

				// Next, make sure that the value is not on the ignore list.
				if (optional)
					continue;

				list = to_srv ? req_skipval_ : resp_skipval_;

				while (list->name) {
					if (list->id == hsig->hdr[i].id) {
						break;
					}
					list++;
				}

				if (list->name) {
					continue;
				}

				/* Looks like it's not on the list, so let's output a cleaned-up
				 * version up to HTTP_MAX_SHOW. */
				std::string tmp;
				for (const char *ptr = val;; ++ptr) {
					if (tmp.size() >= HTTP_MAX_SHOW) {
						break;
					}

					if (*ptr < 0x20 || static_cast<uint8_t>(*ptr) >= 0x80 || *ptr == ']' || *ptr == '|') {
						break;
					}
					tmp.push_back(*ptr);
				}

				if (!tmp.empty()) {
					append_format(ss, "=[%s]", tmp.c_str());
				}
			}
		} else {

			append_format(ss, "%s%s", had_prev ? "," : "", hsig->hdr[i].name->c_str());
			had_prev = 1;

			if (hsig->hdr[i].value) {

				const char *val = hsig->hdr[i].value->c_str();

				std::string tmp;
				for (const char *ptr = val;; ++ptr) {
					if (tmp.size() >= HTTP_MAX_SHOW) {
						break;
					}

					if (*ptr < 0x20 || static_cast<uint8_t>(*ptr) >= 0x80 || *ptr == ']') {
						break;
					}
					tmp.push_back(*ptr);
				}

				if (!tmp.empty()) {
					append_format(ss, "=[%s]", tmp.c_str());
				}
			}
		}
	}

	append_format(ss, ":");

	list     = to_srv ? req_common_ : resp_common_;
	had_prev = false;

	while (list->name) {
		uint32_t i;
		for (i = 0; i < hsig->hdr.size(); i++) {
			if (hsig->hdr[i].id == list->id) {
				break;
			}
		}

		if (i == hsig->hdr.size()) {
			append_format(ss, "%s%s", had_prev ? "," : "", list->name);
			had_prev = 1;
		}

		list++;
	}

	append_format(ss, ":");

	if (hsig->sw) {

		const char *val = hsig->sw->c_str();

		std::string tmp;
		for (const char *ptr = val;; ++ptr) {
			if (tmp.size() >= HTTP_MAX_SHOW) {
				break;
			}

			if (*ptr < 0x20 || static_cast<uint8_t>(*ptr) >= 0x80 || *ptr == ']') {
				break;
			}
			tmp.push_back(*ptr);
		}

		if (!tmp.empty()) {
			append_format(ss, "%s", tmp.c_str());
		}
	}

	return ss.str();
}

// Dump signature flags.
std::string http_context_t::dump_flags(const http_sig *hsig, const http_sig_record *m) {

	std::stringstream ss;

	if (hsig->dishonest)
		append_format(ss, " dishonest");

	if (!hsig->sw)
		append_format(ss, " anonymous");

	if (m && m->generic)
		append_format(ss, " generic");

	std::string ret = ss.str();

	if (!ret.empty()) {
		return ret.substr(1);
	} else {
		return "none";
	}
}

/* Score signature differences. For unknown signatures, the presumption is that
 * they identify apps, so the logic is quite different from TCP. */
void http_context_t::score_nat(bool to_srv, const packet_flow *f, libp0f_context_t *libp0f_context) {

	http_sig_record *m = f->http_tmp.matched;
	host_data *hd;
	std::shared_ptr<http_sig> ref;

	uint8_t score        = 0;
	uint8_t diff_already = 0;
	uint16_t reason      = 0;

	if (to_srv) {
		hd  = f->client;
		ref = hd->http_req_os;
	} else {
		hd  = f->server;
		ref = hd->http_resp;

		// If the signature is for a different port, don't read too much into it.
		if (hd->http_resp_port != f->srv_port) {
			ref = nullptr;
		}
	}

	if (!m) {
		/* No match. The user is probably running another app; this is only of
		 * interest if a server progresses from known to unknown. We can't
		 * compare two unknown server sigs with that much confidence. */
		if (!to_srv && ref && ref->matched) {
			DEBUG("[#] HTTP server signature changed from known to unknown.\n");
			score += 4;
			reason |= NAT_TO_UNK;
		}

		goto header_check;
	}

	if (m->class_id == InvalidId) {
		/* Got a match for an application signature. Make sure it runs on the
		 * OS we have on file... */
		process_context.verify_tool_class(to_srv, f, m->sys, libp0f_context);

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

		/* Ooh, spiffy: a match for an OS signature! There will be about two
		 * uses for this code, ever. */
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
		 * signature doesn't match host data. */
		if (!diff_already && hd->last_name_id != m->name_id) {

			DEBUG("[#] Matched HTTP OS signature different than host data.\n");
			score += 4;
			reason |= NAT_OS_SIG;
		}
	}

	/* If we have determined that U-A looks legit, but the OS doesn't match,
	 * that's a clear sign of trouble. */
	if (to_srv && m->class_id == InvalidId && f->http_tmp.sw && !f->http_tmp.dishonest) {

		size_t i;

		for (i = 0; i < ua_map_.size(); i++)
			if (strstr(f->http_tmp.sw->c_str(), ua_map_[i].name.c_str()))
				break;

		if (i != ua_map_.size()) {

			if (ua_map_[i].id != hd->last_name_id) {

				DEBUG("[#] Otherwise plausible User-Agent points to another OS.\n");
				score += 4;
				reason |= NAT_APP_UA;

				if (!hd->bad_sw)
					hd->bad_sw = 1;

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

		if (hdr_diff < -HTTP_MAX_DATE_DIFF || hdr_diff > recv_diff + HTTP_MAX_DATE_DIFF) {

			DEBUG("[#] HTTP 'Date' distance too high (%ld in %ld sec).\n",
				  hdr_diff,
				  recv_diff);

			score += 4;
			reason |= NAT_APP_DATE;

		} else {
			DEBUG("[#] HTTP 'Date' distance seems fine (%ld in %ld sec).\n",
				  hdr_diff,
				  recv_diff);
		}
	}

	process_context.add_nat_score(to_srv, f, reason, score, libp0f_context);
}

// Look up HTTP signature, create an observation.
void http_context_t::fingerprint_http(bool to_srv, packet_flow *f, libp0f_context_t *libp0f_context) {

	http_sig_record *m;
	const char *lang = nullptr;

	http_find_match(to_srv, &f->http_tmp, 0);

	libp0f_context->start_observation(to_srv ? "http request" : "http response", 4, to_srv, f);

	if ((m = f->http_tmp.matched)) {

		observf(libp0f_context, (m->class_id == InvalidId) ? "app" : "os", "%s%s%s",
				fp_context.fp_os_names[m->name_id].c_str(),
				m->flavor ? " " : "",
				m->flavor ? m->flavor->c_str() : "");

	} else
		libp0f_context->observation_field("app", nullptr);

	if (f->http_tmp.lang && isalpha((*f->http_tmp.lang)[0]) && isalpha((*f->http_tmp.lang)[1]) && !isalpha((*f->http_tmp.lang)[2])) {

		uint8_t lh  = LANG_HASH((*f->http_tmp.lang)[0], (*f->http_tmp.lang)[1]);
		uint8_t pos = 0;

		while (languages[lh][pos]) {
			if ((*f->http_tmp.lang)[0] == languages[lh][pos][0] && (*f->http_tmp.lang)[1] == languages[lh][pos][1]) {
				break;
			}
			pos += 2;
		}

		if (!languages[lh][pos]) {
			libp0f_context->observation_field("lang", nullptr);
		} else {
			lang = languages[lh][pos + 1];
			libp0f_context->observation_field("lang", lang);
		}

	} else {
		libp0f_context->observation_field("lang", "none");
	}

	libp0f_context->observation_field("params", dump_flags(&f->http_tmp, m).c_str());
	libp0f_context->observation_field("raw_sig", dump_sig(to_srv, &f->http_tmp).c_str());

	score_nat(to_srv, f, libp0f_context);

	// Save observations needed to score future responses.
	if (!to_srv) {

		// For server response, always store the signature.
		f->server->http_resp = std::make_shared<http_sig>(f->http_tmp);

		f->server->http_resp->hdr.clear();
		f->server->http_resp->sw   = {};
		f->server->http_resp->lang = {};
		f->server->http_resp->via  = {};

		f->server->http_resp_port = f->srv_port;

		if (lang)
			f->server->language = lang;

		if (m) {
			if (m->class_id != InvalidId) {

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

		if (lang)
			f->client->language = lang;

		if (m) {
			if (m->class_id != InvalidId) {

				// Client request - only OS sig is of any note.
				f->client->http_req_os = std::make_shared<http_sig>(f->http_tmp);

				f->client->http_req_os->hdr.clear();
				f->client->http_req_os->sw   = {};
				f->client->http_req_os->lang = {};
				f->client->http_req_os->via  = {};
				f->client->last_class_id     = m->class_id;
				f->client->last_name_id      = m->name_id;
				f->client->last_flavor       = m->flavor;

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

// Parse name=value pairs into a signature.
bool http_context_t::parse_pairs(bool to_srv, packet_flow *f, bool can_get_more, libp0f_context_t *libp0f_context) {

	size_t plen = to_srv ? f->request.size() : f->response.size();

	uint32_t off;

	// Try to parse name: value pairs.
	while ((off = f->http_pos) < plen) {

		const char *const pay = to_srv ? f->request.data() : f->response.data();

		// Empty line? Dispatch for fingerprinting!
		if (pay[off] == '\r' || pay[off] == '\n') {

			f->http_tmp.recv_date = process_context.get_unix_time();

			fingerprint_http(to_srv, f, libp0f_context);

			/* If this is a request, flush the collected signature and prepare
			 * for parsing the response. If it's a response, just shut down HTTP
			 * parsing on this flow. */
			if (to_srv) {
				f->http_req_done = 1;
				f->http_pos      = 0;
				f->http_tmp      = {};
				return true;
			} else {
				f->in_http = -1;
				return false;
			}
		}

		// Looks like we're getting a header value. See if we have room for it.
		if (f->http_tmp.hdr.size() >= HTTP_MAX_HDRS) {
			DEBUG("[#] Too many HTTP headers in a %s.\n", to_srv ? "request" : "response");
			f->in_http = -1;
			return false;
		}

		// Try to extract header name.
		uint32_t nlen = 0;

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
			return false;
		}

		/* At this point, header name starts at f->http_pos, and has nlen bytes.
		 * Skip ':' and a subsequent whitespace next. */
		off++;

		if (off < plen && isblank(pay[off])) off++;

		uint32_t vstart = off;
		uint32_t vlen   = 0;

		// Find the next \n.
		while (off < plen && vlen <= HTTP_MAX_HDR_VAL && pay[off] != '\n') {
			off++;
			vlen++;
		}

		if (vlen > HTTP_MAX_HDR_VAL) {
			DEBUG("[#] HTTP %s header value length exceeded.\n",
				  to_srv ? "request" : "response");
			f->in_http = -1;
			return true;
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
		if (pay[off - 1] == '\r')
			vlen--;

		/* Header value starts at vstart, and has vlen bytes (may be zero).
		 * Record this in the signature. */
		const uint32_t hid = lookup_hdr(std::string(pay + f->http_pos, nlen), false);

		http_hdr new_hdr;
		new_hdr.id = hid;

		if (hid == InvalidId) {
			// Header ID not found, store literal value.
			new_hdr.name = std::string(pay + f->http_pos, nlen);
		} else {
			// Found - update Bloom filter.
			f->http_tmp.hdr_bloom4 |= bloom4_64(hid);
		}

		/* If there's a value, store that too. For U-A and Server, also update
		 * 'sw'; and for requests, collect Accept-Language. */
		if (vlen) {

			std::string val = std::string(pay + vstart, vlen);

			new_hdr.value = val;

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
					f->http_tmp.date = parse_date(val.c_str());
					break;
				case HDR_VIA:
				case HDR_XFF:
					f->http_tmp.via = val;
					break;
				}
			}
		}

		// Moving on...
		f->http_tmp.hdr.push_back(std::move(new_hdr));
		f->http_pos = off + 1;
	}

	if (!can_get_more) {
		DEBUG("[#] End of HTTP %s before end of headers.\n",
			  to_srv ? "request" : "response");
		f->in_http = -1;
	}

	return can_get_more;
}

// Pre-register essential headers.
http_context_t::http_context_t() {

	memcpy(&req_optional_, &req_optional_init, sizeof(req_optional_));
	memcpy(&resp_optional_, &resp_optional_init, sizeof(resp_optional_));
	memcpy(&req_common_, &req_common_init, sizeof(req_common_));
	memcpy(&resp_common_, &resp_common_init, sizeof(resp_common_));
	memcpy(&req_skipval_, &req_skipval_init, sizeof(req_skipval_));
	memcpy(&resp_skipval_, &resp_skipval_init, sizeof(resp_skipval_));

	// Do not change - other code depends on the ordering of first 6 entries.
	lookup_hdr("User-Agent", true);      // 0
	lookup_hdr("Server", true);          // 1
	lookup_hdr("Accept-Language", true); // 2
	lookup_hdr("Via", true);             // 3
	lookup_hdr("X-Forwarded-For", true); // 4
	lookup_hdr("Date", true);            // 5

	uint32_t i;
	i = 0;
	while (req_optional_[i].name) {
		req_optional_[i].id = lookup_hdr(req_optional_[i].name, true);
		i++;
	}

	i = 0;
	while (resp_optional_[i].name) {
		resp_optional_[i].id = lookup_hdr(resp_optional_[i].name, true);
		i++;
	}

	i = 0;
	while (req_skipval_[i].name) {
		req_skipval_[i].id = lookup_hdr(req_skipval_[i].name, true);
		i++;
	}

	i = 0;
	while (resp_skipval_[i].name) {
		resp_skipval_[i].id = lookup_hdr(resp_skipval_[i].name, true);
		i++;
	}

	i = 0;
	while (req_common_[i].name) {
		req_common_[i].id = lookup_hdr(req_common_[i].name, true);
		i++;
	}

	i = 0;
	while (resp_common_[i].name) {
		resp_common_[i].id = lookup_hdr(resp_common_[i].name, true);
		i++;
	}
}

// Register new HTTP signature.
void http_context_t::http_register_sig(bool to_srv, uint8_t generic, uint32_t sig_class, uint32_t sig_name, const ext::optional<std::string> &sig_flavor, uint32_t label_id, const std::vector<uint32_t> &sys, ext::string_view value, uint32_t line_no) {

	auto hsig = std::make_unique<http_sig>();

	parser in(value);

	// http_ver
	if (in.match('0')) {
		hsig->http_ver = 0;
	} else if (in.match('1')) {
		hsig->http_ver = 1;
	} else if (in.match('*')) {
		hsig->http_ver = -1;
	} else {
		FATAL("Bad HTTP version in line %u.", line_no);
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// horder
	if (in.peek() != ':') {
		do {
			if (hsig->hdr.size() >= HTTP_MAX_HDRS) {
				FATAL("Too many headers listed in line %u.", line_no);
			}

			bool optional = in.match('?');

			std::string horder_key;
			if (!in.match([](char ch) { return isalnum(ch) || ch == '-' || ch == '_'; }, &horder_key)) {
				FATAL("Malformed header name in line %u.", line_no);
			}

			const uint32_t id = lookup_hdr(horder_key, true);

			http_hdr new_hdr;
			new_hdr.id       = id;
			new_hdr.optional = optional;

			if (!optional) {
				hsig->hdr_bloom4 |= bloom4_64(id);
			}

			if (in.match('=')) {
				if (!in.match('[')) {
					FATAL("Missing '[' after '=' in line %u.", line_no);
				}

				std::string horder_value;
				if (!in.match([](char ch) { return ch != ']'; }, &horder_value)) {
					FATAL("Malformed signature in line %u.", line_no);
				}

				new_hdr.value = horder_value;

				if (!in.match(']')) {
					FATAL("Malformed signature in line %u.", line_no);
				}
			}

			hsig->hdr.push_back(new_hdr);
		} while (in.match(','));
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// habsent
	if (in.peek() != ':') {
		do {
			if (hsig->miss.size() >= HTTP_MAX_HDRS) {
				FATAL("Too many headers listed in line %u.", line_no);
			}

			std::string habsent_key;
			if (!in.match([](char ch) { return isalnum(ch) || ch == '-' || ch == '_'; }, &habsent_key)) {
				FATAL("Malformed header name in line %u.", line_no);
			}

			uint32_t id = lookup_hdr(habsent_key, true);
			hsig->miss.push_back(id);
		} while (in.match(','));
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// exp_sw
	std::string exp_sw;
	if (in.match_any(&exp_sw)) {
		if (exp_sw.find(':') != std::string::npos) {
			FATAL("Malformed signature in line %u.", line_no);
		}
		hsig->sw = exp_sw;
	}

	http_find_match(to_srv, hsig, 1);

	if (hsig->matched) {
		FATAL("Signature in line %u is already covered by line %u.",
			  line_no,
			  hsig->matched->line_no);
	}

	http_sig_record hrec;
	hrec.class_id = sig_class;
	hrec.name_id  = sig_name;
	hrec.flavor   = sig_flavor;
	hrec.label_id = label_id;
	hrec.sys      = sys;
	hrec.line_no  = line_no;
	hrec.generic  = generic;
	hrec.sig      = std::move(hsig);

	sigs_[to_srv].push_back(std::move(hrec));
}

// Register new HTTP signature.
void http_context_t::http_parse_ua(ext::string_view value, uint32_t line_no) {

	parser in(value);
	do {

		std::string system_str;
		if (!in.match([](char ch) { return isalnum(ch) || strchr(NAME_CHARS, ch); }, &system_str)) {
			FATAL("Malformed system name in line %u.", line_no);
		}

		uint32_t id = lookup_name_id(system_str);

		ext::optional<std::string> name;
		if (in.match('=')) {

			if (!in.match('[')) {
				FATAL("Missing '[' after '=' in line %u.", line_no);
			}

			std::string value_str;
			if (!in.match([](char ch) { return ch != ']'; }, &value_str)) {
				FATAL("Malformed signature in line %u.", line_no);
			}

			if (!in.match(']')) {
				FATAL("Malformed signature in line %u.", line_no);
			}

			name = value_str;
		}

		ua_map_record record;
		record.id   = id;
		record.name = (!name) ? fp_context.fp_os_names[id] : *name;
		ua_map_.push_back(record);

	} while (in.match(','));

	if (!in.eof()) {
		FATAL("Malformed signature in line %u.", line_no);
	}
}

/* Examine request or response; returns 1 if more data needed and plausibly
 * can be read. Note that the buffer is always NUL-terminated. */
bool http_context_t::process_http(bool to_srv, packet_flow *f, libp0f_context_t *libp0f_context) {

	// Already decided this flow is not worth tracking?
	if (f->in_http < 0)
		return false;

	if (to_srv) {

		const char *const pay = f->request.data();
		bool can_get_more     = (f->request.size() < MAX_FLOW_DATA);

		// Request done, but pending response?
		if (f->http_req_done)
			return true;

		if (!f->in_http) {

			uint8_t chr;
			const char *sig_at;

			// Ooh, new flow!
			if (f->request.size() < 15)
				return can_get_more;

			// Scan until \n, or until binary data spotted.
			uint32_t off = f->http_pos;

			// We only care about GET and HEAD requests at this point.
			if (!off && strncmp(pay, "GET /", 5) &&
				strncmp(pay, "HEAD /", 6)) {
				DEBUG("[#] Does not seem like a GET / HEAD request.\n");
				f->in_http = -1;
				return false;
			}

			while (off < f->request.size() && off < HTTP_MAX_URL && (chr = pay[off]) != '\n') {
				if (chr != '\r' && (chr < 0x20 || chr > 0x7f)) {
					DEBUG("[#] Not HTTP - character 0x%02x encountered.\n", chr);
					f->in_http = -1;
					return false;
				}

				off++;
			}

			// Newline too far or too close?
			if (off == HTTP_MAX_URL || off < 14) {
				DEBUG("[#] Not HTTP - newline offset %u.\n", off);
				f->in_http = -1;
				return false;
			}

			// Not enough data yet?
			if (off == f->request.size()) {
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
				return false;
			}

			f->http_tmp.http_ver = (sig_at[7] == '1');

			f->in_http  = 1;
			f->http_pos = off + 1;

			DEBUG("[#] HTTP detected.\n");
		}

		return parse_pairs(1, f, can_get_more, libp0f_context);

	} else {

		const char *const pay = f->response.data();
		bool can_get_more     = (f->response.size() < MAX_FLOW_DATA);

		// Response before request? Bail out.
		if (!f->in_http || !f->http_req_done) {
			f->in_http = -1;
			return false;
		}

		if (!f->http_gotresp1) {

			uint8_t chr;

			if (f->response.size() < 13)
				return can_get_more;

			// Scan until \n, or until binary data spotted.
			uint32_t off = f->http_pos;

			while (off < f->response.size() && off < HTTP_MAX_URL && (chr = pay[off]) != '\n') {
				if (chr != '\r' && (chr < 0x20 || chr > 0x7f)) {
					DEBUG("[#] Invalid HTTP response - character 0x%02x encountered.\n",
						  chr);
					f->in_http = -1;
					return false;
				}

				off++;
			}

			// Newline too far or too close?
			if (off == HTTP_MAX_URL || off < 13) {
				DEBUG("[#] Invalid HTTP response - newline offset %u.\n", off);
				f->in_http = -1;
				return false;
			}

			// Not enough data yet?
			if (off == f->response.size()) {
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
				return false;
			}

			f->http_tmp.http_ver = (pay[7] == '1');
			f->http_pos          = off + 1;
			DEBUG("[#] HTTP response starts correctly.\n");
		}

		return parse_pairs(0, f, can_get_more, libp0f_context);
	}
}
