/*
   p0f - vaguely configurable bits
   -------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef P0F_CONFIG_H_
#define P0F_CONFIG_H_

#include <cstddef>

/* ------------------------------------------
 * Things you may reasonably want to change *
 * -----------------------------------------*/

// Default location of p0f.fp:
#ifndef FP_FILE
#define FP_FILE "p0f.fp"
#endif

// Initial permissions on log files:
#ifndef LOG_MODE
#define LOG_MODE 0600
#endif

// Initial permissions on API sockets:
#ifndef API_MODE
#define API_MODE 0666
#endif

// Default connection and host cache sizes (adjustable via -m):
#ifndef MAX_HOSTS
#define MAX_CONN 1000
#define MAX_HOSTS 10000
#endif

// Default connection and host time limits (adjustable via -t):
#ifndef HOST_IDLE_LIMIT
#define CONN_MAX_AGE 30     // seconds
#define HOST_IDLE_LIMIT 120 // minutes
#endif

// Default number of API connections permitted (adjustable via -c):
#ifndef API_MAX_CONN
#define API_MAX_CONN 20
#endif

// Maximum TTL distance for non-fuzzy signature matching:
#ifndef MAX_DIST
#define MAX_DIST 35
#endif

/* ----------------------
 * Really obscure stuff *
 * ---------------------*/

// Percentage of host entries / flows to prune when limits exceeded:
constexpr int KILL_PERCENT = 10;

// PCAP snapshot length:
constexpr int SNAPLEN = 65535;

// Maximum request, response size to keep per flow:
constexpr size_t MAX_FLOW_DATA = 8192;

// Maximum number of TCP options we will process (< 256):
constexpr int MAX_TCP_OPT = 24;

/* Minimum and maximum frequency for timestamp clock (Hz). Note that RFC
 * 1323 permits 1 - 1000 Hz . At 1000 Hz, the 32-bit counter overflows
 * after about 50 days. */
constexpr double MIN_TSCALE = 0.7;
constexpr int MAX_TSCALE    = 1500;

/* Minimum and maximum interval (ms) for measuring timestamp progrssion. This
 * is used to make sure the timestamps are fresh enough to be of any value,
 * and that the measurement is not affected by network performance too
 * severely. */
constexpr int MIN_TWAIT = 25;
constexpr int MAX_TWAIT = 1000 * 60 * 10;

/* Time window in which to tolerate timestamps going back slightly or
 * otherwise misbehaving during NAT checks (ms): */
constexpr int TSTAMP_GRACE = 100;

// Maximum interval between packets used for TS-based NAT checks (ms):
constexpr int MAX_NAT_TS = 1000 * 60 * 60 * 24;

// Minimum port drop to serve as a NAT detection signal:
constexpr int MIN_PORT_DROP = 64;

/* Threshold before letting NAT detection make a big deal out of TTL change
 * for remote hosts (this is to account for peering changes): */
constexpr int SMALL_TTL_CHG = 2;

/* The distance up to which the system is considered to be local, and therefore
 * the SMALL_TTL_CHG threshold should not be taken account: */
constexpr int LOCAL_TTL_LIMIT = 5;

/* The distance past which the system is considered to be really distant,
 * and therefore, changes within SMALL_TTL_CHG should be completely ignored: */
constexpr int NEAR_TTL_LIMIT = 9;

// Number of packet scores to keep for NAT detection (< 256):
constexpr int NAT_SCORES = 32;

// Number of hash buckets for p0f.fp signatures:
constexpr int SIG_BUCKETS = 64;

// Number of hash buckets for active connections:
constexpr int FLOW_BUCKETS = 256;

// Number of hash buckets for host data:
constexpr int HOST_BUCKETS = 1024;

// Cache expiration interval (every n packets received):
constexpr int EXPIRE_INTERVAL = 50;

/* Non-alphanumeric chars to permit in OS names. This is to allow 'sys' syntax
 * to be used unambiguously, yet allow some freedom: */
constexpr char NAME_CHARS[] = " ./-_!?()";

// Special window size and MSS used by p0f-sendsyn, and detected by p0f:
constexpr int SPECIAL_MSS = 1331;
constexpr int SPECIAL_WIN = 1337;

/* Maximum length of an HTTP URL line we're willing to entertain. The same
 * limit is also used for the first line of a response: */
constexpr int HTTP_MAX_URL = 1024;

// Maximum number of HTTP headers:
constexpr int HTTP_MAX_HDRS = 32;

// Maximum length of a header name:
constexpr int HTTP_MAX_HDR_NAME = 32;

// Maximum length of a header value:
constexpr int HTTP_MAX_HDR_VAL = 1024;

// Maximum length of a header value for display purposes:
constexpr int HTTP_MAX_SHOW = 200;

// Maximum HTTP 'Date' progression jitter to overlook (s):
constexpr int HTTP_MAX_DATE_DIFF = 10;

#endif
