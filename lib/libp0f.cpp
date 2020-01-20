
#include "p0f/libp0f.h"
#include "p0f/api.h"
#include "p0f/debug.h"
#include "p0f/util.h"

libp0f::libp0f(const char *filename, const libp0f_settings &new_settings)
	: settings(new_settings) {

	fp_context.read_config(filename ? filename : FP_FILE);
}

libp0f::libp0f(const char *filename) {
	fp_context.read_config(filename ? filename : FP_FILE);
}

libp0f::~libp0f() {
	process_context.destroy_all_hosts();
}

void libp0f::begin_observation(const char *keyword, uint8_t field_cnt, bool to_srv, const packet_flow *f) {
	start_observation(process_context.get_unix_time(), keyword, field_cnt, to_srv, f);
}

// Process API queries.
void libp0f::handle_query(const p0f_api_query *q, p0f_api_response *r) {

	*r       = {};
	r->magic = P0F_RESP_MAGIC;

	if (q->magic != P0F_QUERY_MAGIC) {
		WARN("Query with bad magic (0x%x).", q->magic);
		r->status = P0F_STATUS_BADQUERY;
		return;
	}

	const host_data *h = nullptr;
	switch (q->addr_type) {
	case P0F_ADDR_IPV4:
	case P0F_ADDR_IPV6:
		h = process_context.lookup_host(q->addr, q->addr_type);
		break;
	default:
		WARN("Query with unknown address type %u.\n", q->addr_type);
		r->status = P0F_STATUS_BADQUERY;
		return;
	}

	if (!h) {
		r->status = P0F_STATUS_NOMATCH;
		return;
	}

	r->status     = P0F_STATUS_OK;
	r->first_seen = h->first_seen;
	r->last_seen  = h->last_seen;
	r->total_conn = h->total_conn;

	if (h->last_name_id != InvalidId) {
		strncpy(r->os_name, fp_context.fp_os_names_[h->last_name_id].c_str(), P0F_STR_MAX + 1);
		r->os_name[P0F_STR_MAX] = '\0';

		if (h->last_flavor) {
			strncpy(r->os_flavor, h->last_flavor->c_str(), P0F_STR_MAX + 1);
			r->os_flavor[P0F_STR_MAX] = '\0';
		}
	}

	if (h->http_name_id != InvalidId) {
		strncpy(r->http_name, fp_context.fp_os_names_[h->http_name_id].c_str(), P0F_STR_MAX + 1);
		r->http_name[P0F_STR_MAX] = '\0';

		if (h->http_flavor) {
			strncpy(r->http_flavor, h->http_flavor->c_str(), P0F_STR_MAX + 1);
			r->http_flavor[P0F_STR_MAX] = '\0';
		}
	}

	if (h->link_type) {
		strncpy(r->link_type, h->link_type->c_str(), P0F_STR_MAX + 1);
		r->link_type[P0F_STR_MAX] = '\0';
	}

	if (h->language) {
		strncpy(r->language, h->language, P0F_STR_MAX + 1);
		r->language[P0F_STR_MAX] = '\0';
	}

	r->bad_sw      = h->bad_sw;
	r->last_nat    = h->last_nat;
	r->last_chg    = h->last_chg;
	r->up_mod_days = h->up_mod_days;
	r->distance    = h->distance;
	r->os_match_q  = h->last_quality;

	if (h->last_up_min != -1) {
		r->uptime_min = h->last_up_min;
	}
}

void libp0f::parse_packet_frame(struct timeval ts, const uint8_t *data, size_t packet_len) {
	process_context.parse_packet_frame(ts, data, packet_len);
}
