/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_API

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-inl.h"
#include "api.h"
#include "config.h"
#include "debug.h"
#include "p0f.h"
#include "process.h"
#include "readfp.h"
#include "types.h"

void handle_query(struct p0f_api_query *q, struct p0f_api_response *r);

/* Process API queries. */
void handle_query(struct p0f_api_query *q, struct p0f_api_response *r) {

	struct host_data *h;

	memset(r, 0, sizeof(struct p0f_api_response));

	r->magic = P0F_RESP_MAGIC;

	if (q->magic != P0F_QUERY_MAGIC) {
		WARN("Query with bad magic (0x%x).", q->magic);
		r->status = P0F_STATUS_BADQUERY;
		return;
	}

	switch (q->addr_type) {
	case P0F_ADDR_IPV4:
	case P0F_ADDR_IPV6:
		h = lookup_host(q->addr, q->addr_type);
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

	if (h->last_name_id != -1) {
		strncpy(r->os_name, fp_os_names[h->last_name_id], P0F_STR_MAX + 1);
		r->os_name[P0F_STR_MAX] = '\0';

		if (h->last_flavor) {
			strncpy(r->os_flavor, h->last_flavor, P0F_STR_MAX + 1);
			r->os_flavor[P0F_STR_MAX] = '\0';
		}
	}

	if (h->http_name_id != -1) {
		strncpy(r->http_name, fp_os_names[h->http_name_id], P0F_STR_MAX + 1);
		r->http_name[P0F_STR_MAX] = '\0';

		if (h->http_flavor) {
			strncpy(r->http_flavor, h->http_flavor, P0F_STR_MAX + 1);
			r->http_flavor[P0F_STR_MAX] = '\0';
		}
	}

	if (h->link_type) {
		strncpy(r->link_type, h->link_type, P0F_STR_MAX + 1);
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
