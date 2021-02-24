/*
   p0f - TCP/IP packet matching
   ----------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ostream>
#include <sstream>
#include <unistd.h>
#include <vector>

#include <netinet/in.h>
#include <sys/types.h>

#include "Reader.h"
#include "hash.h"
#include "p0f/api.h"
#include "p0f/config.h"
#include "p0f/debug.h"
#include "p0f/fp_tcp.h"
#include "p0f/libp0f.h"
#include "p0f/process.h"
#include "p0f/readfp.h"
#include "p0f/tcp.h"
#include "p0f/util.h"

namespace {

// Figure out what the TTL distance might have been for an unknown sig.
constexpr uint8_t guess_dist(uint8_t ttl) {
	if (ttl <= 32) {
		return 32 - ttl;
	}

	if (ttl <= 64) {
		return 64 - ttl;
	}

	if (ttl <= 128) {
		return 128 - ttl;
	}

	return 255 - ttl;
}

/* Figure out if window size is a multiplier of MSS or MTU. We don't take window
 * scaling into account, because neither do TCP stack developers. */
int16_t detect_win_multi(const std::unique_ptr<tcp_sig> &ts, bool *use_mtu, uint16_t syn_mss) {

	uint16_t win  = ts->win;
	int32_t mss   = ts->mss;
	int32_t mss12 = mss - 12;

	if (!win || mss < 100 || ts->win_type != WIN_TYPE_NORMAL) {
		return -1;
	}

#define RET_IF_DIV(_div, _use_mtu, _desc)                                                                                 \
	do {                                                                                                                  \
		if ((_div) && !(win % (_div))) {                                                                                  \
			*use_mtu = (_use_mtu);                                                                                        \
			DEBUG("[#] Window size %u is a multiple of %s [%llu].\n", win, _desc, static_cast<unsigned long long>(_div)); \
			return win / (_div);                                                                                          \
		}                                                                                                                 \
	} while (0)

	RET_IF_DIV(mss, false, "MSS");

	// Some systems will sometimes subtract 12 bytes when timestamps are in use.
	if (ts->ts1) {
		RET_IF_DIV(mss12, false, "MSS - 12");
	}

	/* Some systems use MTU on the wrong interface, so let's check for the most
	 * common case. */
	RET_IF_DIV(1500 - MIN_TCP4, false, "MSS (MTU = 1500, IPv4)");
	RET_IF_DIV(1500 - MIN_TCP4 - 12, false, "MSS (MTU = 1500, IPv4 - 12)");

	if (ts->ip_ver == IP_VER6) {

		RET_IF_DIV(1500 - MIN_TCP6, false, "MSS (MTU = 1500, IPv6)");
		RET_IF_DIV(1500 - MIN_TCP6 - 12, false, "MSS (MTU = 1500, IPv6 - 12)");
	}

	// Some systems use MTU instead of MSS:
	RET_IF_DIV(mss + MIN_TCP4, true, "MTU (IPv4)");
	RET_IF_DIV(mss + ts->tot_hdr, true, "MTU (actual size)");
	if (ts->ip_ver == IP_VER6) {
		RET_IF_DIV(mss + MIN_TCP6, true, "MTU (IPv6)");
	}
	RET_IF_DIV(1500, true, "MTU (1500)");

	// On SYN+ACKs, some systems use of the peer:
	if (syn_mss) {
		RET_IF_DIV(syn_mss, false, "peer MSS");
		RET_IF_DIV(syn_mss - 12, false, "peer MSS - 12");
	}

#undef RET_IF_DIV

	return -1;
}

// Dump unknown signature.
std::string dump_sig(const packet_data *pk, const std::unique_ptr<tcp_sig> &ts, uint16_t syn_mss) {

	std::ostringstream ss;

	bool win_mtu;
	int16_t win_m;
	uint32_t i;
	uint8_t dist = guess_dist(pk->ttl);

	if (dist > MAX_DIST) {
		append_format(ss, "%u:%u+?:%u:", pk->ip_ver, pk->ttl, pk->ip_opt_len);
	} else {
		append_format(ss, "%u:%u+%u:%u:", pk->ip_ver, pk->ttl, dist, pk->ip_opt_len);
	}

	/* Detect a system echoing back MSS from p0f-sendsyn queries, suggest using
	 a wildcard in such a case. */
	if (pk->mss == SPECIAL_MSS && pk->tcp_type == (TCP_SYN | TCP_ACK)) {
		append_format(ss, "*:");
	} else {
		append_format(ss, "%u:", pk->mss);
	}

	win_m = detect_win_multi(ts, &win_mtu, syn_mss);

	if (win_m > 0) {
		append_format(ss, "%s*%u", win_mtu ? "mtu" : "mss", win_m);
	} else {
		append_format(ss, "%u", pk->win);
	}

	append_format(ss, ",%u:", pk->wscale);

	for (i = 0; i < pk->opt_layout.size(); ++i) {

		switch (pk->opt_layout[i]) {
		case TCPOPT_EOL:
			append_format(ss, "%seol+%u", i ? "," : "", pk->opt_eol_pad);
			break;
		case TCPOPT_NOP:
			append_format(ss, "%snop", i ? "," : "");
			break;
		case TCPOPT_MAXSEG:
			append_format(ss, "%smss", i ? "," : "");
			break;
		case TCPOPT_WSCALE:
			append_format(ss, "%sws", i ? "," : "");
			break;
		case TCPOPT_SACKOK:
			append_format(ss, "%ssok", i ? "," : "");
			break;
		case TCPOPT_SACK:
			append_format(ss, "%ssack", i ? "," : "");
			break;
		case TCPOPT_TSTAMP:
			append_format(ss, "%sts", i ? "," : "");
			break;
		default:
			append_format(ss, "%s?%u", i ? "," : "", pk->opt_layout[i]);
		}
	}

	append_format(ss, ":");

	if (pk->quirks) {

		bool sp = false;

		auto maybe_cm = [&ss, &sp](const char *str) {
			append_format(ss, sp ? ",%s" : "%s", str);
			sp = true;
		};

		if (pk->quirks & QUIRK_DF) {
			maybe_cm("df");
		}
		if (pk->quirks & QUIRK_NZ_ID) {
			maybe_cm("id+");
		}
		if (pk->quirks & QUIRK_ZERO_ID) {
			maybe_cm("id-");
		}
		if (pk->quirks & QUIRK_ECN) {
			maybe_cm("ecn");
		}
		if (pk->quirks & QUIRK_NZ_MBZ) {
			maybe_cm("0+");
		}
		if (pk->quirks & QUIRK_FLOW) {
			maybe_cm("flow");
		}
		if (pk->quirks & QUIRK_ZERO_SEQ) {
			maybe_cm("seq-");
		}
		if (pk->quirks & QUIRK_NZ_ACK) {
			maybe_cm("ack+");
		}
		if (pk->quirks & QUIRK_ZERO_ACK) {
			maybe_cm("ack-");
		}
		if (pk->quirks & QUIRK_NZ_URG) {
			maybe_cm("uptr+");
		}
		if (pk->quirks & QUIRK_URG) {
			maybe_cm("urgf+");
		}
		if (pk->quirks & QUIRK_PUSH) {
			maybe_cm("pushf+");
		}
		if (pk->quirks & QUIRK_OPT_ZERO_TS1) {
			maybe_cm("ts1-");
		}
		if (pk->quirks & QUIRK_OPT_NZ_TS2) {
			maybe_cm("ts2+");
		}
		if (pk->quirks & QUIRK_OPT_EOL_NZ) {
			maybe_cm("opt+");
		}
		if (pk->quirks & QUIRK_OPT_EXWS) {
			maybe_cm("exws");
		}
		if (pk->quirks & QUIRK_OPT_BAD) {
			maybe_cm("bad");
		}
	}

	if (pk->pay_len) {
		append_format(ss, ":+");
	} else {
		append_format(ss, ":0");
	}

	return ss.str();
}

// Dump signature-related flags.
std::string dump_flags(packet_data *pk, const std::unique_ptr<tcp_sig> &ts) {

	std::ostringstream ss;

	if (ts->matched) {
		if (ts->matched->generic) {
			append_format(ss, " generic");
		}

		if (ts->fuzzy) {
			append_format(ss, " fuzzy");
		}

		if (ts->matched->bad_ttl) {
			append_format(ss, " random_ttl");
		}
	}

	if (ts->dist > MAX_DIST) {
		append_format(ss, " excess_dist");
	}

	if (pk->tos) {
		append_format(ss, " tos:0x%02x", pk->tos);
	}

	std::string ret = ss.str();

	if (!ret.empty()) {
		return ret.substr(1);
	} else {
		return "none";
	}
}

}

/* Convert packet_data to a simplified tcp_sig representation
   suitable for signature matching. Compute hashes. */
void tcp_context_t::packet_to_sig(packet_data *pk, const std::unique_ptr<tcp_sig> &ts) {

	ts->opt_hash = hash32(pk->opt_layout.data(), pk->opt_layout.size());

	ts->quirks      = pk->quirks;
	ts->opt_eol_pad = pk->opt_eol_pad;
	ts->ip_opt_len  = pk->ip_opt_len;
	ts->ip_ver      = pk->ip_ver;
	ts->ttl         = pk->ttl;
	ts->mss         = pk->mss;
	ts->win         = pk->win;
	ts->win_type    = WIN_TYPE_NORMAL; // Keep as-is.
	ts->wscale      = pk->wscale;
	ts->pay_class   = !!pk->pay_len;
	ts->tot_hdr     = pk->tot_hdr;
	ts->ts1         = pk->ts1;
	ts->recv_ms     = ctx_->process_context.get_unix_time_ms();
	ts->matched     = nullptr;
	ts->fuzzy       = 0;
	ts->dist        = 0;
}

/* Compare current signature with historical data, draw conclusions. This
   is called only for OS sigs. */
void tcp_context_t::score_nat(bool to_srv, const std::unique_ptr<tcp_sig> &sig, packet_flow *f) {

	uint8_t score        = 0;
	uint8_t diff_already = 0;
	uint16_t reason      = 0;
	int32_t ttl_diff;

	host_data *hd                 = (to_srv) ? f->client : f->server;
	std::unique_ptr<tcp_sig> &ref = (to_srv) ? hd->last_syn : hd->last_synack;

	if (!ref) {

		/* No previous signature of matching type at all. We can perhaps still
		 * check if class / name is the same as on file, as that data might
		 * have been obtained from other types of sigs. */

		if (sig->matched && hd->last_class_id != InvalidId) {

			if (hd->last_name_id != sig->matched->name_id) {

				DEBUG("[#] New TCP signature different OS type than host data.\n");

				reason |= NAT_OS_SIG;
				score += 8;
			}
		}

		goto log_and_update;
	}

	// We have some previous data.
	if (!sig->matched || !ref->matched) {

		/* One or both of the signatures are unknown. Let's see if they differ.
		 * The scoring here isn't too strong, because we don't know if the
		 * unrecognized signature isn't originating from userland tools. */

		if ((sig->quirks ^ ref->quirks) & ~(QUIRK_ECN | QUIRK_DF | QUIRK_NZ_ID | QUIRK_ZERO_ID)) {

			DEBUG("[#] Non-fuzzy quirks changed compared to previous sig.\n");

			reason |= NAT_UNK_DIFF;
			score += 2;

		} else if (to_srv && sig->opt_hash != ref->opt_hash) {

			/* We only match option layout for SYNs; it may change on SYN+ACK,
			 * and the user may have gaps in SYN+ACK sigs if he ignored our
			 * advice on using p0f-sendsyn. */

			DEBUG("[#] SYN option layout changed compared to previous sig.\n");

			reason |= NAT_UNK_DIFF;
			score += 1;
		}

		// Progression from known to unknown is also of interest for SYNs.
		if (to_srv && sig->matched != ref->matched) {

			DEBUG("[#] SYN signature changed from %s.\n",
				  sig->matched ? "unknown to known" : "known to unknown");

			score += 1;
			reason |= NAT_TO_UNK;
		}

	} else {

		// Both signatures known!
		if (ref->matched->name_id != sig->matched->name_id) {

			DEBUG("[#] TCP signature different OS type on previous sig.\n");
			score += 8;
			reason |= NAT_OS_SIG;

			diff_already = 1;

		} else if (to_srv) {

			// SYN signatures match superficially, but...
			if (ref->matched->label_id != sig->matched->label_id) {

				/* SYN label changes are a weak but useful signal. SYN+ACK
				 * signatures may need less intuitive groupings, so we don't
				 * check that. */

				DEBUG("[#] SYN signature label different on previous sig.\n");
				score += 2;
				reason |= NAT_OS_SIG;

			} else if (ref->matched->line_no != sig->matched->line_no) {

				/* Change in line number is an extremely weak but still
				 * noteworthy signal. */

				DEBUG("[#] SYN signature changes within the same label.\n");
				score += 1;
				reason |= NAT_OS_SIG;

			} else if (sig->fuzzy != ref->fuzzy) {

				// Fuzziness change on a perfectly matched signature?
				DEBUG("[#] SYN signature fuzziness changes.\n");
				score += 1;
				reason |= NAT_FUZZY;
			}
		}
	}

	/* Unless the signatures are already known to differ radically, mismatch
	 * between host data and current sig is of additional note. */
	if (!diff_already && sig->matched && hd->last_class_id != InvalidId && hd->last_name_id != sig->matched->name_id) {

		DEBUG("[#] New OS signature different OS type than host data.\n");
		score += 8;
		reason |= NAT_OS_SIG;
		diff_already = 1;
	}

	/* TTL differences in absence of major signature mismatches is also
	 * interesting, unless the signatures are tagged as "bad TTL", or unless
	 * the difference is barely 1 and the host is distant. */
	ttl_diff = static_cast<int16_t>(sig->ttl) - ref->ttl;

	if (!diff_already && ttl_diff && (!sig->matched || !sig->matched->bad_ttl) && (!ref->matched || !ref->matched->bad_ttl) && (sig->dist <= NEAR_TTL_LIMIT || ttl_diff > 1)) {

		DEBUG("[#] Signature TTL differs by %d (dist = %u).\n", ttl_diff, sig->dist);

		if (sig->dist > LOCAL_TTL_LIMIT && std::abs(ttl_diff) <= SMALL_TTL_CHG) {
			score += 1;
		} else {
			score += 4;
		}

		reason |= NAT_TTL;
	}

	/* Source port going back frequently is of some note, although it will
	 * happen spontaneously every now and then. Require the drop to be by at
	 * least few dozen, to account for simple case of several simultaneously
	 * opened connections arriving in odd order. */
	if (to_srv && hd->last_port && f->cli_port < hd->last_port &&
		hd->last_port - f->cli_port >= MIN_PORT_DROP) {

		DEBUG("[#] Source port drops from %u to %u.\n", hd->last_port, f->cli_port);

		score += 1;
		reason |= NAT_PORT;
	}

	// Change of MTU is always sketchy.
	if (sig->mss != ref->mss) {

		DEBUG("[#] MSS for signature changed from %u to %u.\n", ref->mss, sig->mss);

		score += 1;
		reason |= NAT_MSS;
	}

	/* Check timestamp progression to possibly adjust current score. Don't rate
	 * on TS alone, because some systems may be just randomizing that. */
	if (score && sig->ts1 && ref->ts1) {

		uint64_t ms_diff = sig->recv_ms - ref->recv_ms;

		/* Require a timestamp within the last day; if the apparent TS
		 * progression is much higher than 1 kHz, complain. */
		if (ms_diff < MAX_NAT_TS) {

			uint64_t use_ms = (ms_diff < TSTAMP_GRACE) ? TSTAMP_GRACE : ms_diff;
			uint64_t max_ts = use_ms * MAX_TSCALE / 1000;

			uint32_t ts_diff = sig->ts1 - ref->ts1;

			if (ts_diff > max_ts && (ms_diff >= TSTAMP_GRACE || ~ts_diff > max_ts)) {

				DEBUG("[#] Dodgy timestamp progression across signatures (%d "
					  "in %lu ms).\n",
					  ts_diff,
					  ms_diff);

				score += 4;
				reason |= NAT_TS;

			} else {

				DEBUG("[#] Timestamp consistent across signatures (%d in %lu ms), "
					  "reducing score.\n",
					  ts_diff,
					  ms_diff);

				score /= 2;
			}

		} else {
			DEBUG("[#] Timestamps available, but with bad interval (%lu ms).\n",
				  ms_diff);
		}
	}

log_and_update:

	ctx_->process_context.add_nat_score(to_srv, f, reason, score);

	// Update some of the essential records.
	if (sig->matched) {
		hd->last_class_id = sig->matched->class_id;
		hd->last_name_id  = sig->matched->name_id;
		hd->last_flavor   = sig->matched->flavor;
		hd->last_quality  = (sig->fuzzy * P0F_MATCH_FUZZY) | (sig->matched->generic * P0F_MATCH_GENERIC);
	}

	hd->last_port = f->cli_port;
}

/* Parse TCP-specific bits and register a signature read from p0f.fp.
 * This function is too long. */
void tcp_context_t::tcp_register_sig(bool to_srv, uint8_t generic, uint32_t sig_class, uint32_t sig_name, const ext::optional<std::string> &sig_flavor, uint32_t label_id, const std::vector<uint32_t> &sys, ext::string_view value, uint32_t line_no) {

	int8_t ver;
	int8_t win_type;
	int8_t pay_class;
	std::vector<uint8_t> opt_layout;
	uint8_t bad_ttl = 0;

	Reader in(value);

	// IP version
	if (in.match('4')) {
		ver = IP_VER4;
	} else if (in.match('6')) {
		ver = IP_VER6;
	} else if (in.match('*')) {
		ver = -1;
	} else {
		FATAL("Unrecognized IP version in line %u.", line_no);
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// Initial TTL (possibly ttl+dist or ttl-)
	auto ttl = in.match_if([](char ch) { return isdigit(ch); });
	if (!ttl) {
		FATAL("Malformed signature in line %u.", line_no);
	}
	int ittl = stoi(*ttl);
	if (ittl < 1 || ittl > 255) {
		FATAL("Bogus initial TTL in line %u.", line_no);
	}

	if (in.match('-')) {
		bad_ttl = 1;
	} else if (in.match('+')) {
		auto ttl_add = in.match_if([](char ch) { return isdigit(ch); });
		if (!ttl_add) {
			FATAL("Malformed signature in line %u.", line_no);
		}
		int ittl_add = stoi(*ttl_add);

		if (ittl_add < 0 || ittl + ittl_add > 255) {
			FATAL("Bogus initial TTL in line %u.", line_no);
		}

		ittl += ittl_add;
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// Length of IP options
	auto olen_str = in.match_if([](char ch) { return isdigit(ch); });
	if (!olen_str) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	int olen = stoi(*olen_str);
	if (olen < 0 || olen > 255) {
		FATAL("Bogus IP option length in line %u.", line_no);
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// MSS
	int mss;
	if (in.match('*')) {
		mss = -1;
	} else {
		auto mss_str = in.match_if([](char ch) { return isdigit(ch); });
		if (!mss_str) {
			FATAL("Malformed signature in line %u.", line_no);
		}

		mss = stoi(*mss_str);
		if (mss < 0 || mss > 65535) {
			FATAL("Bogus MSS in line %u.", line_no);
		}
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// window size, followed by comma
	int win;
	if (in.match("*")) {
		win_type = WIN_TYPE_ANY;
		win      = 0;
	} else if (in.match('%')) {
		win_type = WIN_TYPE_MOD;

		auto win_str = in.match_if([](char ch) { return isdigit(ch); });
		if (!win_str) {
			FATAL("Malformed signature in line %u.", line_no);
		}

		win = stoi(*win_str);
		if (win < 2 || win > 65535) {
			FATAL("Bogus '%%' value in line %u.", line_no);
		}
	} else if (in.match("mss*")) {
		win_type = WIN_TYPE_MSS;

		auto win_str = in.match_if([](char ch) { return isdigit(ch); });
		if (!win_str) {
			FATAL("Malformed signature in line %u.", line_no);
		}

		win = stoi(*win_str);
		if (win < 1 || win > 1000) {
			FATAL("Bogus MSS/MTU multiplier in line %u.", line_no);
		}
	} else if (in.match("mtu*")) {
		win_type = WIN_TYPE_MTU;

		auto win_str = in.match_if([](char ch) { return isdigit(ch); });
		if (!win_str) {
			FATAL("Malformed signature in line %u.", line_no);
		}

		win = stoi(*win_str);
		if (win < 1 || win > 1000) {
			FATAL("Bogus MSS/MTU multiplier in line %u.", line_no);
		}
	} else {
		win_type = WIN_TYPE_NORMAL;

		auto win_str = in.match_if([](char ch) { return isdigit(ch); });
		if (!win_str) {
			FATAL("Malformed signature in line %u.", line_no);
		}

		win = stoi(*win_str);
		if (win < 0 || win > 65535) {
			FATAL("Bogus window size in line %u.", line_no);
		}
	}

	if (!in.match(',')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// Window scale
	int scale;
	if (in.match('*')) {
		scale = -1;
	} else {
		auto scale_str = in.match_if([](char ch) { return isdigit(ch); });
		if (!scale_str) {
			FATAL("Malformed signature in line %u.", line_no);
		}

		scale = stoi(*scale_str);
		if (scale < 0 || scale > 255) {
			FATAL("Bogus window scale in line %u.", line_no);
		}
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// Option layout
	int opt_eol_pad = 0;
	while (in.peek() != ':') {

		if (opt_layout.size() >= MAX_TCP_OPT) {
			FATAL("Too many TCP options in line %u.", line_no);
		}

		if (in.match("eol")) {
			opt_layout.push_back(TCPOPT_EOL);

			if (!in.match('+')) {
				FATAL("Malformed EOL option in line %u.", line_no);
			}

			auto eol_str = in.match_if([](char ch) { return isdigit(ch); });
			if (!eol_str) {
				FATAL("Truncated options in line %u.", line_no);
			}

			opt_eol_pad = stoi(*eol_str);
			if (opt_eol_pad < 0 || opt_eol_pad > 255) {
				FATAL("Bogus EOL padding in line %u.", line_no);
			}

			if (in.peek() != ':') {
				FATAL("EOL must be the last option in line %u.", line_no);
			}
		} else if (in.match("nop")) {
			opt_layout.push_back(TCPOPT_NOP);
		} else if (in.match("mss")) {
			opt_layout.push_back(TCPOPT_MAXSEG);
		} else if (in.match("ws")) {
			opt_layout.push_back(TCPOPT_WSCALE);
		} else if (in.match("sok")) {
			opt_layout.push_back(TCPOPT_SACKOK);
		} else if (in.match("sack")) {
			opt_layout.push_back(TCPOPT_SACK);
		} else if (in.match("ts")) {
			opt_layout.push_back(TCPOPT_TSTAMP);
		} else if (in.match('?')) {

			auto opt_str = in.match_if([](char ch) { return isdigit(ch); });
			if (!opt_str) {
				FATAL("Malformed '?' option in line %u.", line_no);
			}

			const int optno = stoi(*opt_str);
			if (optno < 0 || optno > 255) {
				FATAL("Bogus '?' option in line %u.", line_no);
			}

			opt_layout.push_back(optno);

			if (in.peek() != ':' && in.peek() != ',') {
				FATAL("Malformed '?' option in line %u.", line_no);
			}

		} else {
			FATAL("Unrecognized TCP option in line %u.", line_no);
		}

		if (in.peek() == ':') {
			break;
		}

		if (!in.match(',')) {
			FATAL("Malformed TCP options in line %u.", line_no);
		}
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	const uint32_t opt_hash = hash32(opt_layout.data(), opt_layout.size());

	// Quirks
	uint32_t quirks = 0;
	while (in.peek() != ':') {
		if (in.match("df")) {
			if (ver == IP_VER6) {
				FATAL("'df' is not valid for IPv6 in line %u.", line_no);
			}

			quirks |= QUIRK_DF;
		} else if (in.match("id+")) {
			if (ver == IP_VER6) {
				FATAL("'id+' is not valid for IPv6 in line %u.", line_no);
			}

			quirks |= QUIRK_NZ_ID;
		} else if (in.match("id-")) {
			if (ver == IP_VER6) {
				FATAL("'id-' is not valid for IPv6 in line %u.", line_no);
			}

			quirks |= QUIRK_ZERO_ID;
		} else if (in.match("ecn")) {
			quirks |= QUIRK_ECN;
		} else if (in.match("0+")) {
			if (ver == IP_VER6) {
				FATAL("'0+' is not valid for IPv6 in line %u.", line_no);
			}

			quirks |= QUIRK_NZ_MBZ;
		} else if (in.match("flow")) {
			if (ver == IP_VER4) {
				FATAL("'flow' is not valid for IPv4 in line %u.", line_no);
			}

			quirks |= QUIRK_FLOW;
		} else if (in.match("seq-")) {
			quirks |= QUIRK_ZERO_SEQ;
		} else if (in.match("ack+")) {
			quirks |= QUIRK_NZ_ACK;
		} else if (in.match("ack-")) {
			quirks |= QUIRK_ZERO_ACK;
		} else if (in.match("uptr+")) {
			quirks |= QUIRK_NZ_URG;
		} else if (in.match("urgf+")) {
			quirks |= QUIRK_URG;
		} else if (in.match("pushf+")) {
			quirks |= QUIRK_PUSH;
		} else if (in.match("ts1-")) {
			quirks |= QUIRK_OPT_ZERO_TS1;
		} else if (in.match("ts2+")) {
			quirks |= QUIRK_OPT_NZ_TS2;
		} else if (in.match("opt+")) {
			quirks |= QUIRK_OPT_EOL_NZ;
		} else if (in.match("exws")) {
			quirks |= QUIRK_OPT_EXWS;
		} else if (in.match("bad")) {
			quirks |= QUIRK_OPT_BAD;
		} else {
			FATAL("Unrecognized quirk in line %u.", line_no);
		}

		if (in.peek() == ':') {
			break;
		}

		if (!in.match(',')) {
			FATAL("Malformed quirks in line %u.", line_no);
		}
	}

	if (!in.match(':')) {
		FATAL("Malformed signature in line %u.", line_no);
	}

	// Payload class
	if (in.match('*')) {
		pay_class = -1;
	} else if (in.match('0')) {
		pay_class = 0;
	} else if (in.match('+')) {
		pay_class = 1;
	} else {
		FATAL("Malformed payload class in line %u.", line_no);
	}

	// Phew, okay, we're done. Now, create tcp_sig...
	auto tsig = std::make_unique<tcp_sig>();

	tsig->opt_hash    = opt_hash;
	tsig->opt_eol_pad = static_cast<uint8_t>(opt_eol_pad);
	tsig->quirks      = quirks;
	tsig->ip_opt_len  = static_cast<uint8_t>(olen);
	tsig->ip_ver      = ver;
	tsig->ttl         = static_cast<uint8_t>(ittl);
	tsig->mss         = mss;
	tsig->win         = static_cast<uint16_t>(win);
	tsig->win_type    = static_cast<uint8_t>(win_type);
	tsig->wscale      = static_cast<int16_t>(scale);
	tsig->pay_class   = pay_class;

	// No need to set ts1, recv_ms, match, fuzzy, dist
	tcp_find_match(to_srv, tsig, 1, 0);

	if (tsig->matched) {
		FATAL("Signature in line %u is already covered by line %u.",
			  line_no, tsig->matched->line_no);
	}

	// Everything checks out, so let's register it.
	uint32_t bucket = opt_hash % SIG_BUCKETS;

	tcp_sig_record trec;
	trec.generic  = generic;
	trec.class_id = sig_class;
	trec.name_id  = sig_name;
	trec.flavor   = sig_flavor;
	trec.label_id = label_id;
	trec.sys      = sys;
	trec.line_no  = line_no;
	trec.sig      = std::move(tsig);
	trec.bad_ttl  = bad_ttl;
	sigs_[to_srv][bucket].push_back(std::move(trec));

	// All done, phew.
}

// Fingerprint SYN or SYN+ACK.
std::unique_ptr<tcp_sig> tcp_context_t::fingerprint_tcp(bool to_srv, packet_data *pk, packet_flow *f) {

	auto sig = std::make_unique<tcp_sig>();
	packet_to_sig(pk, sig);

	/* Detect packets generated by p0f-sendsyn; they require special
	 * handling to provide the user with response fingerprints, but not
	 * interfere with NAT scores and such. */
	if (pk->tcp_type == TCP_SYN && pk->win == SPECIAL_WIN && pk->mss == SPECIAL_MSS) {
		f->sendsyn = true;
	}

	if (to_srv) {
		ctx_->begin_observation(f->sendsyn ? "sendsyn probe" : "syn", 4, 1, f);
	} else {
		ctx_->begin_observation(f->sendsyn ? "sendsyn response" : "syn+ack", 4, 0, f);
	}

	tcp_find_match(to_srv, sig, 0, f->syn_mss);

	const tcp_sig_record *const m = sig->matched;
	if (m) {
		report_observation(ctx_, (m->class_id == InvalidId || f->sendsyn) ? "app" : "os", "%s%s%s",
						   ctx_->fp_context.os_names_[m->name_id].c_str(),
						   m->flavor ? " " : "",
						   m->flavor ? m->flavor->c_str() : "");

	} else {
		ctx_->observation_field("os", nullptr);
	}

	if (m && m->bad_ttl) {
		report_observation(ctx_, "dist", "<= %u", sig->dist);
	} else {
		if (to_srv) {
			f->client->distance = sig->dist;
		} else {
			f->server->distance = sig->dist;
		}

		report_observation(ctx_, "dist", "%u", sig->dist);
	}

	ctx_->observation_field("params", dump_flags(pk, sig).c_str());

	ctx_->observation_field("raw_sig", dump_sig(pk, sig, f->syn_mss).c_str());

	if (pk->tcp_type == TCP_SYN) {
		f->syn_mss = pk->mss;
	}

	// That's about as far as we go with non-OS signatures.
	if (m && m->class_id == InvalidId) {
		ctx_->process_context.verify_tool_class(to_srv, f, m->sys);
		return nullptr;
	}

	if (f->sendsyn) {
		return nullptr;
	}

	score_nat(to_srv, sig, f);
	return sig;
}

/* Perform uptime detection. This is the only FP function that gets called not
   only on SYN or SYN+ACK, but also on ACK traffic. */
void tcp_context_t::check_ts_tcp(bool to_srv, packet_data *pk, packet_flow *f) {

	uint32_t ts_diff;
	uint64_t ms_diff;
	double ffreq;

	if (!pk->ts1 || f->sendsyn) {
		return;
	}

	/* If we're getting SYNs very rapidly, last_syn may be changing too quickly
	 to be of any use. Perhaps lock into an older value? */

	if (to_srv) {
		if (f->cli_tps || !f->client->last_syn || !f->client->last_syn->ts1) {
			return;
		}

		ms_diff = ctx_->process_context.get_unix_time_ms() - f->client->last_syn->recv_ms;
		ts_diff = pk->ts1 - f->client->last_syn->ts1;

	} else {
		if (f->srv_tps || !f->server->last_synack || !f->server->last_synack->ts1) {
			return;
		}

		ms_diff = ctx_->process_context.get_unix_time_ms() - f->server->last_synack->recv_ms;
		ts_diff = pk->ts1 - f->server->last_synack->ts1;
	}

	/* Wait at least 25 ms, and not more than 10 minutes, for at least 5
	 * timestamp ticks. Allow the timestamp to go back slightly within a short
	 * window, too - we may be receiving packets a bit out of order. */

	if (ms_diff < MIN_TWAIT || ms_diff > MAX_TWAIT) {
		return;
	}

	if (ts_diff < 5 || (ms_diff < TSTAMP_GRACE && (~ts_diff) / 1000 < MAX_TSCALE / TSTAMP_GRACE)) {
		return;
	}

	if (ts_diff > ~ts_diff) {
		ffreq = (~ts_diff * -1000.0 / ms_diff);
	} else {
		ffreq = (ts_diff * 1000.0 / ms_diff);
	}

	if (ffreq < MIN_TSCALE || ffreq > MAX_TSCALE) {

		/* Allow bad reading on SYN, as this may be just an artifact of IP
		 * sharing or OS change. */

		if (pk->tcp_type != TCP_SYN) {
			if (to_srv) {
				f->cli_tps = -1;
			} else {
				f->srv_tps = -1;
			}
		}

		DEBUG("[#] Bad %s TS frequency: %.02f Hz (%d ticks in %lu ms).\n",
			  to_srv ? "client" : "server", ffreq, ts_diff, ms_diff);

		return;
	}

	auto freq = static_cast<uint32_t>(ffreq);

	// Round the frequency neatly.
	if (freq == 0) {
		freq = 1;
	} else if (freq >= 1 && freq <= 10) {
		// no change
	} else if (freq >= 11 && freq <= 50) {
		freq = (freq + 3) / 5 * 5;
	} else if (freq >= 51 && freq <= 100) {
		freq = (freq + 7) / 10 * 10;
	} else if (freq >= 101 && freq <= 500) {
		freq = (freq + 33) / 50 * 50;
	} else {
		freq = (freq + 67) / 100 * 100;
	}

	if (to_srv) {
		f->cli_tps = freq;
	} else {
		f->srv_tps = freq;
	}

	uint32_t up_min      = pk->ts1 / freq / 60;
	uint32_t up_mod_days = 0xFFFFFFFF / (freq * 60 * 60 * 24);

	ctx_->begin_observation("uptime", 2, to_srv, f);

	if (to_srv) {
		f->client->last_up_min = up_min;
		f->client->up_mod_days = up_mod_days;
	} else {
		f->server->last_up_min = up_min;
		f->server->up_mod_days = up_mod_days;
	}

	report_observation(ctx_, "uptime", "%u days %u hrs %u min (modulo %u days)",
					   (up_min / 60 / 24), (up_min / 60) % 24, up_min % 60,
					   up_mod_days);

	report_observation(ctx_, "raw_freq", "%.02f Hz", ffreq);
}

// See if any of the p0f.fp signatures matches the collected data.
void tcp_context_t::tcp_find_match(bool to_srv, const std::unique_ptr<tcp_sig> &ts, uint8_t dupe_det, uint16_t syn_mss) {

	tcp_sig_record *fmatch = nullptr;
	tcp_sig_record *gmatch = nullptr;

	uint32_t bucket = ts->opt_hash % SIG_BUCKETS;

	bool use_mtu      = false;
	int16_t win_multi = detect_win_multi(ts, &use_mtu, syn_mss);

	for (size_t i = 0; i < sigs_[to_srv][bucket].size(); ++i) {

		tcp_sig_record *ref                  = &sigs_[to_srv][bucket][i];
		const std::unique_ptr<tcp_sig> &refs = ref->sig;

		uint8_t fuzzy       = 0;
		uint32_t ref_quirks = refs->quirks;

		if (ref->sig->opt_hash != ts->opt_hash) {
			continue;
		}

		/* If the p0f.fp signature has no IP version specified, we need
		 * to remove IPv6-specific quirks from it when matching IPv4
		 * packets, and vice versa. */
		if (refs->ip_ver == -1) {
			ref_quirks &= ((ts->ip_ver == IP_VER4) ? ~(QUIRK_FLOW) : ~(QUIRK_DF | QUIRK_NZ_ID | QUIRK_ZERO_ID));
		}

		if (ref_quirks != ts->quirks) {

			uint32_t deleted = (ref_quirks ^ ts->quirks) & ref_quirks,
					 added   = (ref_quirks ^ ts->quirks) & ts->quirks;

			/* If there is a difference in quirks, but it amounts to 'df' or
			 * 'id+' disappearing, or 'id-' or 'ecn' appearing, allow a fuzzy match. */
			if (fmatch || (deleted & ~(QUIRK_DF | QUIRK_NZ_ID)) ||
				(added & ~(QUIRK_ZERO_ID | QUIRK_ECN))) {
				continue;
			}

			fuzzy = 1;
		}

		// Fixed parameters.
		if (refs->opt_eol_pad != ts->opt_eol_pad ||
			refs->ip_opt_len != ts->ip_opt_len) {
			continue;
		}

		// TTL matching, with a provision to allow fuzzy match.
		if (ref->bad_ttl) {
			if (refs->ttl < ts->ttl) {
				continue;
			}

		} else {
			if (refs->ttl < ts->ttl || refs->ttl - ts->ttl > MAX_DIST) {
				fuzzy = 1;
			}
		}

		// Simple wildcards.
		if (refs->mss != -1 && refs->mss != ts->mss) {
			continue;
		}
		if (refs->wscale != -1 && refs->wscale != ts->wscale) {
			continue;
		}
		if (refs->pay_class != -1 && refs->pay_class != ts->pay_class) {
			continue;
		}

		// Window size.
		if (ts->win_type != WIN_TYPE_NORMAL) {

			// Comparing two p0f.fp signatures.
			if (refs->win_type != ts->win_type || refs->win != ts->win) {
				continue;
			}

		} else {

			// Comparing real-world stuff.
			switch (refs->win_type) {

			case WIN_TYPE_NORMAL:

				if (refs->win != ts->win) {
					continue;
				}
				break;

			case WIN_TYPE_MOD:

				if (ts->win % refs->win) {
					continue;
				}
				break;

			case WIN_TYPE_MSS:

				if (use_mtu || refs->win != win_multi) {
					continue;
				}
				break;

			case WIN_TYPE_MTU:

				if (!use_mtu || refs->win != win_multi) {
					continue;
				}
				break;

				// WIN_TYPE_ANY
			}
		}

		// Got a match? If not fuzzy, return. If fuzzy, keep looking.
		if (!fuzzy) {

			if (!ref->generic) {

				ts->matched = ref;
				ts->fuzzy   = 0;
				ts->dist    = refs->ttl - ts->ttl;
				return;

			} else if (!gmatch) {
				gmatch = ref;
			}

		} else if (!fmatch) {
			fmatch = ref;
		}
	}

	// OK, no definitive match so far...
	if (dupe_det) {
		return;
	}

	/* If we found a generic signature, and nothing better, let's just use
	 that. */

	if (gmatch) {

		ts->matched = gmatch;
		ts->fuzzy   = 0;
		ts->dist    = gmatch->sig->ttl - ts->ttl;
		return;
	}

	// No fuzzy matching for userland tools.
	if (fmatch && fmatch->class_id == InvalidId) {
		return;
	}

	/* Let's try to guess distance if no match; or if match TTL out of
	 range. */

	if (!fmatch || fmatch->sig->ttl < ts->ttl ||
		(!fmatch->bad_ttl && fmatch->sig->ttl - ts->ttl > MAX_DIST)) {
		ts->dist = guess_dist(ts->ttl);
	} else {
		ts->dist = fmatch->sig->ttl - ts->ttl;
	}

	// Record the outcome.
	ts->matched = fmatch;

	if (fmatch) {
		ts->fuzzy = 1;
	}
}
