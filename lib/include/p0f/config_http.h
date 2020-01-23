
#ifndef P0F_CONFIG_HTTP_H_
#define P0F_CONFIG_HTTP_H_

#include "config.h"
#include "fp_http.h"

/* Headers that should be tagged as optional by the HTTP fingerprinter in any
 * generated signatures: */

// A structure used for looking up various headers internally in fp_http.c:
struct http_id {
	const char *name;
	uint32_t id;
};

constexpr http_id req_optional_init[] = {
	{"Cookie", 0},
	{"Referer", 0},
	{"Origin", 0},
	{"Range", 0},
	{"If-Modified-Since", 0},
	{"If-None-Match", 0},
	{"Via", 0},
	{"X-Forwarded-For", 0},
	{"Authorization", 0},
	{"Proxy-Authorization", 0},
	{"Cache-Control", 0},
	{nullptr, 0},
};

constexpr http_id resp_optional_init[] = {
	{"Set-Cookie", 0},
	{"Last-Modified", 0},
	{"ETag", 0},
	{"Content-Length", 0},
	{"Content-Disposition", 0},
	{"Cache-Control", 0},
	{"Expires", 0},
	{"Pragma", 0},
	{"Location", 0},
	{"Refresh", 0},
	{"Content-Range", 0},
	{"Vary", 0},
	{nullptr, 0},
};

/* Common headers that are expected to be present at all times, and deserve
 * a special mention if absent in a signature: */
constexpr http_id req_common_init[] = {
	{"Host", 0},
	{"User-Agent", 0},
	{"Connection", 0},
	{"Accept", 0},
	{"Accept-Encoding", 0},
	{"Accept-Language", 0},
	{"Accept-Charset", 0},
	{"Keep-Alive", 0},
	{nullptr, 0},
};

constexpr http_id resp_common_init[] = {
	{"Content-Type", 0},
	{"Connection", 0},
	{"Keep-Alive", 0},
	{"Accept-Ranges", 0},
	{"Date", 0},
	{nullptr, 0},
};

/* Headers for which values change depending on the context, and therefore
 * should not be included in proposed signatures. This is on top of the
 * "optional" header lists, which already implies skipping the value. */
constexpr http_id req_skipval_init[] = {
	{"Host", 0},
	{"User-Agent", 0},
	{nullptr, 0},
};

constexpr http_id resp_skipval_init[] = {
	{"Date", 0},
	{"Content-Type", 0},
	{"Server", 0},
	{nullptr, 0},
};

#endif
