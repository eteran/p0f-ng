/*
   p0f - main entry point and all the pcap / unix socket innards
   -------------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_P0F

#include <cerrno>
#include <clocale>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <dirent.h>
#include <getopt.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <pcap/pcap.h>

#ifdef NET_BPF
#include <net/bpf.h>
#else
#include <pcap-bpf.h>
#endif

#include "p0f/alloc-inl.h"
#include "p0f/api.h"
#include "p0f/api_client.h"
#include "p0f/debug.h"
#include "p0f/fp_http.h"
#include "p0f/p0f.h"
#include "p0f/process.h"
#include "p0f/readfp.h"
#include "p0f/tcp.h"

#ifndef PF_INET6
#define PF_INET6 10
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

#define LOGF(...) fprintf(p0f_context.lf, __VA_ARGS__)

namespace {

void start_observation(const char *keyword, uint8_t field_cnt, bool to_srv, const struct packet_flow *f);
void add_observation_field(const char *key, const char *value);

libp0f_context_t libp0f_context = {
	start_observation,
	add_observation_field,
};

struct p0f_context_t {
	char *use_iface   = nullptr; // Interface to listen on
	char *orig_rule   = nullptr; // Original filter rule
	char *switch_user = nullptr; // Target username
	char *log_file    = nullptr; // Binary log file name
	char *api_sock    = nullptr; // API socket file name
	char *fp_file     = nullptr; // Location of p0f.fp

	struct api_client *api_cl = nullptr; // Array with API client state
	FILE *lf                  = nullptr; // Log file stream
	pcap_t *pt                = nullptr; // PCAP capture thingy

	uint32_t api_max_conn = API_MAX_CONN; // Maximum number of API connections
	int32_t null_fd       = -1;           // File descriptor of /dev/null
	int32_t api_fd        = -1;           // API socket descriptor
	uint8_t stop_soon     = 0;            // Ctrl-C or so pressed?
	uint8_t set_promisc   = 0;            // Use promiscuous mode?
	uint8_t obs_fields    = 0;            // No of pending observation fields
	uint8_t daemon_mode   = 0;            // Running in daemon mode?
};

p0f_context_t p0f_context;

// Display usage information
[[noreturn]] void usage() {

	constexpr char message[] =
		"Usage: p0f [ ...options... ] [ 'filter rule' ]\n"
		"\n"
		"Network interface options:\n"
		"\n"
		"  -i iface  - listen on the specified network interface\n"
		"  -r file   - read offline pcap data from a given file\n"
		"  -p        - put the listening interface in promiscuous mode\n"
		"  -L        - list all available interfaces\n"
		"\n"
		"Operating mode and output settings:\n"
		"\n"
		"  -f file   - read fingerprint database from 'file' (%s)\n"
		"  -o file   - write information to the specified log file\n"
		"  -s name   - answer to API queries at a named unix socket\n"
		"  -u user   - switch to the specified unprivileged account and chroot\n"
		"  -d        - fork into background (requires -o or -s)\n"
		"\n"
		"Performance-related options:\n"
		"\n"
		"  -S limit  - limit number of parallel API connections (%u)\n"
		"  -t c,h    - set connection / host cache age limits (%us,%um)\n"
		"  -m c,h    - cap the number of active connections / hosts (%u,%u)\n"
		"\n"
		"Optional filter expressions (man tcpdump) can be specified in the command\n"
		"line to prevent p0f from looking at incidental network traffic.\n"
		"\n"
		"Problems? You can reach the author at <lcamtuf@coredump.cx>.\n";

	ERRORF(
		message,
		FP_FILE,
		API_MAX_CONN,
		CONN_MAX_AGE,
		HOST_IDLE_LIMIT,
		MAX_CONN,
		MAX_HOSTS);

	exit(1);
}

// Get rid of unnecessary file descriptors
void close_spare_fds() {

	int32_t i, closed = 0;
	DIR *d;
	struct dirent *de;

	d = opendir("/proc/self/fd");

	if (!d) {
		// Best we could do...
		for (i = 3; i < 256; i++)
			if (!close(i)) closed++;
		return;
	}

	while ((de = readdir(d))) {
		i = atoi(de->d_name);
		if (i > 2 && !close(i)) closed++;
	}

	closedir(d);

	if (closed)
		SAYF("[+] Closed %u file descriptor%s.\n", closed, closed == 1 ? "" : "s");
}

// Create or open log file
void open_log() {

	struct stat st;

	int log_fd = open(p0f_context.log_file, O_WRONLY | O_APPEND | O_NOFOLLOW | O_LARGEFILE);
	if (log_fd >= 0) {

		if (fstat(log_fd, &st))
			PFATAL("fstat() on '%s' failed.", p0f_context.log_file);

		if (!S_ISREG(st.st_mode))
			FATAL("'%s' is not a regular file.", p0f_context.log_file);

	} else {

		if (errno != ENOENT)
			PFATAL("Cannot open '%s'.", p0f_context.log_file);

		log_fd = open(p0f_context.log_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, LOG_MODE);

		if (log_fd < 0)
			PFATAL("Cannot open '%s'.", p0f_context.log_file);
	}

	if (flock(log_fd, LOCK_EX | LOCK_NB))
		FATAL("'%s' is being used by another process.", p0f_context.log_file);

	p0f_context.lf = fdopen(log_fd, "a");

	if (!p0f_context.lf)
		FATAL("fdopen() on '%s' failed.", p0f_context.log_file);

	SAYF("[+] Log file '%s' opened for writing.\n", p0f_context.log_file);
}

// Create and start listening on API socket
void open_api() {

	int32_t old_umask;
	uint32_t i;

	struct sockaddr_un u;
	struct stat st;

	p0f_context.api_fd = socket(PF_UNIX, SOCK_STREAM, 0);

	if (p0f_context.api_fd < 0)
		PFATAL("socket(PF_UNIX) failed.");

	memset(&u, 0, sizeof(u));
	u.sun_family = AF_UNIX;

	if (strlen(p0f_context.api_sock) >= sizeof(u.sun_path))
		FATAL("API socket filename is too long for sockaddr_un (blame Unix).");

	strcpy(u.sun_path, p0f_context.api_sock);

	/* This is bad, but you can't do any better with standard unix socket
	 * semantics today :-( */

	if (!stat(p0f_context.api_sock, &st) && !S_ISSOCK(st.st_mode))
		FATAL("'%s' exists but is not a socket.", p0f_context.api_sock);

	if (unlink(p0f_context.api_sock) && errno != ENOENT)
		PFATAL("unlink('%s') failed.", p0f_context.api_sock);

	old_umask = umask(0777 ^ API_MODE);

	if (bind(p0f_context.api_fd, reinterpret_cast<struct sockaddr *>(&u), sizeof(u)))
		PFATAL("bind() on '%s' failed.", p0f_context.api_sock);

	umask(old_umask);

	if (listen(p0f_context.api_fd, p0f_context.api_max_conn))
		PFATAL("listen() on '%s' failed.", p0f_context.api_sock);

	if (fcntl(p0f_context.api_fd, F_SETFL, O_NONBLOCK))
		PFATAL("fcntl() to set O_NONBLOCK on API listen socket fails.");

	p0f_context.api_cl = new struct api_client[p0f_context.api_max_conn];

	for (i = 0; i < p0f_context.api_max_conn; i++) {
		p0f_context.api_cl[i].fd = -1;
	}

	SAYF("[+] Listening on API socket '%s' (max %u clients).\n",
		 p0f_context.api_sock,
		 p0f_context.api_max_conn);
}

// Show PCAP interface list
void list_interfaces() {

	char pcap_err[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev;
	uint8_t i = 0;

	/* There is a bug in several years' worth of libpcap releases that causes it
	 * to SEGV here if /sys/class/net is not readable. See http://goo.gl/nEnGx */

	if (access("/sys/class/net", R_OK | X_OK) && errno != ENOENT) {
		FATAL("This operation requires access to /sys/class/net/, sorry.");
	}

	if (pcap_findalldevs(&dev, pcap_err) == -1) {
		FATAL("pcap_findalldevs: %s\n", pcap_err);
	}

	if (!dev) {
		FATAL("Can't find any interfaces. Maybe you need to be root?");
	}

	SAYF("\n-- Available interfaces --\n");

	do {

		pcap_addr_t *a = dev->addresses;

		SAYF("\n%3d: Name        : %s\n", i++, dev->name);
		SAYF("     Description : %s\n", dev->description ? dev->description : "-");

		// Let's try to find something we can actually display.
		while (a && a->addr->sa_family != PF_INET && a->addr->sa_family != PF_INET6)
			a = a->next;

		if (a) {

			if (a->addr->sa_family == PF_INET)
				SAYF("     IP address  : %s\n", addr_to_str(reinterpret_cast<uint8_t *>(a->addr) + 4, IP_VER4));
			else
				SAYF("     IP address  : %s\n", addr_to_str(reinterpret_cast<uint8_t *>(a->addr) + 8, IP_VER6));

		} else
			SAYF("     IP address  : (none)\n");

	} while ((dev = dev->next));

	SAYF("\n");

	pcap_freealldevs(dev);
}

// Initialize PCAP capture
void prepare_pcap() {

	char pcap_err[PCAP_ERRBUF_SIZE];
	char *orig_iface = p0f_context.use_iface;

	if (libp0f_context.read_file) {

		if (p0f_context.set_promisc)
			FATAL("Dude, how am I supposed to make a file promiscuous?");

		if (p0f_context.use_iface)
			FATAL("Options -i and -r are mutually exclusive.");

		if (access(libp0f_context.read_file, R_OK))
			PFATAL("Can't access file '%s'.", libp0f_context.read_file);

		p0f_context.pt = pcap_open_offline(libp0f_context.read_file, pcap_err);

		if (!p0f_context.pt) FATAL("pcap_open_offline: %s", pcap_err);

		SAYF("[+] Will read pcap data from file '%s'.\n", libp0f_context.read_file);

	} else {
		if (!p0f_context.use_iface) {
			/* See the earlier note on libpcap SEGV - same problem here.
			 * Also, this returns something stupid on Windows, but hey... */

			if (!access("/sys/class/net", R_OK | X_OK) || errno == ENOENT) {
				pcap_if_t *alldevs = nullptr;
				char error[PCAP_ERRBUF_SIZE];
				if (pcap_findalldevs(&alldevs, error)) {
					FATAL("pcap_findalldevs: %s\n", error);
				}

				p0f_context.use_iface = alldevs->name;
				pcap_freealldevs(alldevs);
			}

			if (!p0f_context.use_iface) {
				FATAL("libpcap is out of ideas; use -i to specify interface.");
			}
		}

		/* PCAP timeouts tend to be broken, so we'll use a very small value
		 * and rely on select() instead. */
		p0f_context.pt = pcap_open_live(p0f_context.use_iface, SNAPLEN, p0f_context.set_promisc, 5, pcap_err);

		if (!orig_iface)
			SAYF("[+] Intercepting traffic on default interface '%s'.\n", p0f_context.use_iface);
		else
			SAYF("[+] Intercepting traffic on interface '%s'.\n", p0f_context.use_iface);

		if (!p0f_context.pt) FATAL("pcap_open_live: %s", pcap_err);
	}

	libp0f_context.link_type = pcap_datalink(p0f_context.pt);
}

// Initialize BPF filtering
void prepare_bpf() {

	struct bpf_program flt;
	memset(&flt, 0, sizeof(flt));

	char *final_rule     = nullptr;
	uint8_t vlan_support = 0;

	/* VLAN matching is somewhat brain-dead: you need to request it explicitly,
	 and it alters the semantics of the remainder of the expression. */

	vlan_support = (pcap_datalink(p0f_context.pt) == DLT_EN10MB);

retry_no_vlan:

	if (!p0f_context.orig_rule) {

		if (vlan_support) {
			final_rule = const_cast<char *>("tcp or (vlan and tcp)");
		} else {
			final_rule = const_cast<char *>("tcp");
		}

	} else {

		if (vlan_support) {
			final_rule = static_cast<char *>(calloc(strlen(p0f_context.orig_rule) * 2 + 64, 1));
			sprintf(final_rule, "(tcp and (%s)) or (vlan and tcp and (%s))",
					p0f_context.orig_rule,
					p0f_context.orig_rule);

		} else {
			final_rule = static_cast<char *>(calloc(strlen(p0f_context.orig_rule) + 16, 1));
			sprintf(final_rule, "tcp and (%s)",
					p0f_context.orig_rule);
		}
	}

	DEBUG("[#] Computed rule: %s\n", final_rule);

	if (pcap_compile(p0f_context.pt, &flt, final_rule, 1, 0)) {
		if (vlan_support) {
			if (p0f_context.orig_rule)
				free(final_rule);

			vlan_support = 0;
			goto retry_no_vlan;
		}

		pcap_perror(p0f_context.pt, "[-] pcap_compile");

		if (!p0f_context.orig_rule)
			FATAL("pcap_compile() didn't work, strange");
		else
			FATAL("Syntax error! See 'man tcpdump' for help on filters.");
	}

	if (pcap_setfilter(p0f_context.pt, &flt))
		FATAL("pcap_setfilter() didn't work, strange.");

	pcap_freecode(&flt);

	if (!p0f_context.orig_rule) {

		SAYF("[+] Default packet filtering configured%s.\n",
			 vlan_support ? " [+VLAN]" : "");

	} else {

		SAYF("[+] Custom filtering rule enabled: %s%s\n",
			 p0f_context.orig_rule ? p0f_context.orig_rule : "tcp",
			 vlan_support ? " [+VLAN]" : "");

		free(final_rule);
	}
}

// Drop privileges and chroot(), with some sanity checks
void drop_privs() {

	struct passwd *pw = getpwnam(p0f_context.switch_user);

	if (!pw)
		FATAL("User '%s' not found.", p0f_context.switch_user);

	if (!strcmp(pw->pw_dir, "/"))
		FATAL("User '%s' must have a dedicated home directory.", p0f_context.switch_user);

	if (!pw->pw_uid || !pw->pw_gid)
		FATAL("User '%s' must be non-root.", p0f_context.switch_user);

	if (initgroups(pw->pw_name, pw->pw_gid))
		PFATAL("initgroups() for '%s' failed.", p0f_context.switch_user);

	if (chdir(pw->pw_dir))
		PFATAL("chdir('%s') failed.", pw->pw_dir);

	if (chroot(pw->pw_dir))
		PFATAL("chroot('%s') failed.", pw->pw_dir);

	if (chdir("/"))
		PFATAL("chdir('/') after chroot('%s') failed.", pw->pw_dir);

	if (!access("/proc/", F_OK) || !access("/sys/", F_OK))
		FATAL("User '%s' must have a dedicated home directory.", p0f_context.switch_user);

	if (setgid(pw->pw_gid))
		PFATAL("setgid(%u) failed.", pw->pw_gid);

	if (setuid(pw->pw_uid))
		PFATAL("setuid(%u) failed.", pw->pw_uid);

	if (getegid() != pw->pw_gid || geteuid() != pw->pw_uid)
		FATAL("Inconsistent euid / egid after dropping privs.");

	SAYF("[+] Privileges dropped: uid %u, gid %u, root '%s'.\n",
		 pw->pw_uid, pw->pw_gid, pw->pw_dir);
}

// Enter daemon mode.
void fork_off() {

	fflush(nullptr);
	int32_t npid = fork();

	if (npid < 0) PFATAL("fork() failed.");

	if (!npid) {

		/* Let's assume all this is fairly unlikely to fail, so we can live
	   with the parent possibly proclaiming success prematurely. */

		if (dup2(p0f_context.null_fd, 0) < 0) PFATAL("dup2() failed.");

		/* If stderr is redirected to a file, keep that fd and use it for
		 * normal output. */
		if (isatty(2)) {
			if (dup2(p0f_context.null_fd, 1) < 0 || dup2(p0f_context.null_fd, 2) < 0)
				PFATAL("dup2() failed.");
		} else {
			if (dup2(2, 1) < 0)
				PFATAL("dup2() failed.");
		}

		close(p0f_context.null_fd);
		p0f_context.null_fd = -1;

		if (chdir("/"))
			PFATAL("chdir('/') failed.");

		setsid();

	} else {
		SAYF("[+] Daemon process created, PID %u (stderr %s).\n", npid,
			 isatty(2) ? "not kept" : "kept as-is");

		SAYF("\nGood luck, you're on your own now!\n");

		exit(0);
	}
}

// Handler for Ctrl-C and related signals
void abort_handler(int sig) {
	(void)sig;

	if (p0f_context.stop_soon)
		exit(1);

	p0f_context.stop_soon = 1;
}

// Regenerate pollfd data for poll()
uint32_t regen_pfds(struct pollfd *pfds, struct api_client **ctable) {
	uint32_t i;
	uint32_t count = 2;

	pfds[0].fd     = pcap_fileno(p0f_context.pt);
	pfds[0].events = (POLLIN | POLLERR | POLLHUP);

	DEBUG("[#] Recomputing pollfd data, pcap_fd = %d.\n", pfds[0].fd);

	if (!p0f_context.api_sock)
		return 1;

	pfds[1].fd     = p0f_context.api_fd;
	pfds[1].events = (POLLIN | POLLERR | POLLHUP);

	for (i = 0; i < p0f_context.api_max_conn; i++) {

		if (p0f_context.api_cl[i].fd == -1) {
			continue;
		}

		ctable[count] = &p0f_context.api_cl[i];

		/* If we haven't received a complete query yet, wait for POLLIN.
		 * Otherwise, we want to write stuff. */

		if (p0f_context.api_cl[i].in_off < sizeof(struct p0f_api_query))
			pfds[count].events = (POLLIN | POLLERR | POLLHUP);
		else
			pfds[count].events = (POLLOUT | POLLERR | POLLHUP);

		pfds[count++].fd = p0f_context.api_cl[i].fd;
	}

	return count;
}

// Process API queries.
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
		strncpy(r->os_name, libp0f_context.fp_os_names[h->last_name_id], P0F_STR_MAX + 1);
		r->os_name[P0F_STR_MAX] = '\0';

		if (h->last_flavor) {
			strncpy(r->os_flavor, h->last_flavor, P0F_STR_MAX + 1);
			r->os_flavor[P0F_STR_MAX] = '\0';
		}
	}

	if (h->http_name_id != -1) {
		strncpy(r->http_name, libp0f_context.fp_os_names[h->http_name_id], P0F_STR_MAX + 1);
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

// Event loop! Accepts and dispatches pcap data, API queries, etc.
void live_event_loop() {

	/* The huge problem with winpcap on cygwin is that you can't get a file
	 * descriptor suitable for poll() / select() out of it:
	 *
	 * http://www.winpcap.org/pipermail/winpcap-users/2009-April/003179.html
	 *
	 * The only alternatives seem to be additional processes / threads, a
	 * nasty busy loop, or a ton of Windows-specific code. If you need API
	 * queries on Windows, you are welcome to fix this :-) */

	// We need room for pcap, and possibly p0f_context.api_fd + api_clients.
	auto pfds   = static_cast<struct pollfd *>(calloc((1 + (p0f_context.api_sock ? (1 + p0f_context.api_max_conn) : 0)), sizeof(struct pollfd)));
	auto ctable = static_cast<struct api_client **>(calloc((1 + (p0f_context.api_sock ? (1 + p0f_context.api_max_conn) : 0)), sizeof(struct api_client *)));

	uint32_t pfd_count = regen_pfds(pfds, ctable);

	if (!p0f_context.daemon_mode)
		SAYF("[+] Entered main event loop.\n\n");

	while (!p0f_context.stop_soon) {

		/* We had a 250 ms timeout to keep Ctrl-C responsive without resortng
		 * to silly sigaction hackery or unsafe signal handler code.
		 * Unfortunately, if poll() timeout is much longer than pcap timeout,
		 * we end up with dropped packets on VMs. Seems like a kernel bug, but
		 * for now, this loop is a bit busier than it needs to be... */

	poll_again:

		int32_t pret = poll(pfds, pfd_count, 10);
		if (pret < 0) {
			if (errno == EINTR)
				break;
			PFATAL("poll() failed.");
		}

		if (!pret) {
			if (p0f_context.log_file)
				fflush(p0f_context.lf);
			continue;
		}

		// Examine pfds...
		for (uint32_t cur = 0; cur < pfd_count; cur++) {
			if (pfds[cur].revents & (POLLERR | POLLHUP)) {
				switch (cur) {
				case 0:
					FATAL("Packet capture interface is down.");
				case 1:
					FATAL("API socket is down.");
				default:
					// Shut down API connection and free its state.
					DEBUG("[#] API connection on fd %d closed.\n", pfds[cur].fd);

					close(pfds[cur].fd);
					ctable[cur]->fd = -1;

					pfd_count = regen_pfds(pfds, ctable);
					goto poll_again;
				}
			}

			if (pfds[cur].revents & POLLOUT) {
				switch (cur) {
				case 0:
				case 1:
					FATAL("Unexpected POLLOUT on fd %d.\n", cur);
				default: {

					// Write API response, restart state when complete.
					if (ctable[cur]->in_off < sizeof(struct p0f_api_query))
						FATAL("Inconsistent p0f_api_response state.\n");

					ssize_t i = write(pfds[cur].fd, (&ctable[cur]->out_data) + ctable[cur]->out_off, sizeof(struct p0f_api_response) - ctable[cur]->out_off);

					if (i <= 0) PFATAL("write() on API socket fails despite POLLOUT.");

					ctable[cur]->out_off += i;

					// All done? Back to square zero then!
					if (ctable[cur]->out_off == sizeof(struct p0f_api_response)) {

						ctable[cur]->in_off = ctable[cur]->out_off = 0;
						pfds[cur].events                           = (POLLIN | POLLERR | POLLHUP);
					}
				}
				}
			}

			if (pfds[cur].revents & POLLIN) {
				switch (cur) {
				case 0:
					// Process traffic on the capture interface.
					if (pcap_dispatch(p0f_context.pt, -1, parse_packet, reinterpret_cast<u_char *>(&libp0f_context)) < 0)
						FATAL("Packet capture interface is down.");
					break;
				case 1:
					// Accept new API connection, limits permitting.
					if (!p0f_context.api_sock)
						FATAL("Unexpected API connection.");

					if (pfd_count - 2 < p0f_context.api_max_conn) {
						uint32_t i;
						for (i = 0; i < p0f_context.api_max_conn && p0f_context.api_cl[i].fd >= 0; i++) {
						}

						if (i == p0f_context.api_max_conn) FATAL("Inconsistent API connection data.");

						p0f_context.api_cl[i].fd = accept(p0f_context.api_fd, nullptr, nullptr);

						if (p0f_context.api_cl[i].fd < 0) {

							WARN("Unable to handle API connection: accept() fails.");

						} else {

							if (fcntl(p0f_context.api_cl[i].fd, F_SETFL, O_NONBLOCK))
								PFATAL("fcntl() to set O_NONBLOCK on API connection fails.");

							p0f_context.api_cl[i].in_off  = 0;
							p0f_context.api_cl[i].out_off = 0;
							pfd_count                     = regen_pfds(pfds, ctable);

							DEBUG("[#] Accepted new API connection, fd %d.\n", p0f_context.api_cl[i].fd);

							goto poll_again;
						}

					} else
						WARN("Too many API connections (use -S to adjust).\n");

					break;

				default: {
					// Receive API query, dispatch when complete.
					if (ctable[cur]->in_off >= sizeof(struct p0f_api_query))
						FATAL("Inconsistent p0f_api_query state.\n");

					ssize_t i = read(pfds[cur].fd,
									 (&ctable[cur]->in_data) + ctable[cur]->in_off,
									 sizeof(struct p0f_api_query) - ctable[cur]->in_off);

					if (i < 0)
						PFATAL("read() on API socket fails despite POLLIN.");

					ctable[cur]->in_off += i;

					// Query in place? Compute response and prepare to send it back.
					if (ctable[cur]->in_off == sizeof(struct p0f_api_query)) {

						handle_query(&ctable[cur]->in_data, &ctable[cur]->out_data);
						pfds[cur].events = (POLLOUT | POLLERR | POLLHUP);
					}
				}
				}
			}

			// Processed all reported updates already? If so, bail out early.
			if (pfds[cur].revents && !--pret) {
				break;
			}
		}
	}

	free(ctable);
	free(pfds);

	WARN("User-initiated shutdown.");
}

// Simple event loop for processing offline captures.
void offline_event_loop() {

	if (!p0f_context.daemon_mode)
		SAYF("[+] Processing capture data.\n\n");

	while (!p0f_context.stop_soon) {
		if (pcap_dispatch(p0f_context.pt, -1, parse_packet, reinterpret_cast<u_char *>(&libp0f_context)) <= 0) {
			return;
		}
	}

	WARN("User-initiated shutdown.");
}

// Open log entry.
void start_observation(const char *keyword, uint8_t field_cnt, bool to_srv, const struct packet_flow *f) {

	if (p0f_context.obs_fields)
		FATAL("Premature end of observation.");

	if (!p0f_context.daemon_mode) {
		SAYF(".-[ %s/%u -> ", addr_to_str(f->client->addr, f->client->ip_ver),
			 f->cli_port);
		SAYF("%s/%u (%s) ]-\n|\n", addr_to_str(f->server->addr, f->client->ip_ver),
			 f->srv_port, keyword);

		SAYF("| %-8s = %s/%u\n", to_srv ? "client" : "server",
			 addr_to_str(to_srv ? f->client->addr : f->server->addr, f->client->ip_ver),
			 to_srv ? f->cli_port : f->srv_port);
	}

	if (p0f_context.log_file) {
		char tmp[64];

		time_t ut     = get_unix_time();
		struct tm *lt = localtime(&ut);

		strftime(tmp, 64, "%Y/%m/%d %H:%M:%S", lt);

		LOGF("[%s] mod=%s|cli=%s/%u|", tmp, keyword, addr_to_str(f->client->addr, f->client->ip_ver), f->cli_port);

		LOGF("srv=%s/%u|subj=%s", addr_to_str(f->server->addr, f->server->ip_ver),
			 f->srv_port, to_srv ? "cli" : "srv");
	}

	p0f_context.obs_fields = field_cnt;
}

// Add log item.
void add_observation_field(const char *key, const char *value) {

	if (!p0f_context.obs_fields)
		FATAL("Unexpected observation field ('%s').", key);

	if (!p0f_context.daemon_mode)
		SAYF("| %-8s = %s\n", key, value ? value : "???");

	if (p0f_context.log_file)
		LOGF("|%s=%s", key, value ? value : "???");

	p0f_context.obs_fields--;

	if (!p0f_context.obs_fields) {
		if (!p0f_context.daemon_mode)
			SAYF("|\n`----\n\n");

		if (p0f_context.log_file)
			LOGF("\n");
	}
}

}

// Main entry point
int main(int argc, char **argv) {

	int32_t r;

	setlinebuf(stdout);

	SAYF("--- p0f " VERSION " by Michal Zalewski <lcamtuf@coredump.cx> ---\n\n");

	if (getuid() != geteuid())
		FATAL("Please don't make me setuid. See README for more.\n");

	while ((r = getopt(argc, argv, "+LS:df:i:m:o:pr:s:t:u:")) != -1)
		switch (r) {
		case 'L':
			list_interfaces();
			exit(0);
		case 'S':
			if (p0f_context.api_max_conn != API_MAX_CONN)
				FATAL("Multiple -S options not supported.");

			p0f_context.api_max_conn = atol(optarg);

			if (!p0f_context.api_max_conn || p0f_context.api_max_conn > 100)
				FATAL("Outlandish value specified for -S.");

			break;
		case 'd':
			if (p0f_context.daemon_mode)
				FATAL("Double werewolf mode not supported yet.");

			p0f_context.daemon_mode = 1;
			break;
		case 'f':
			if (p0f_context.fp_file)
				FATAL("Multiple -f options not supported.");

			p0f_context.fp_file = optarg;
			break;
		case 'i':
			if (p0f_context.use_iface)
				FATAL("Multiple -i options not supported (try '-i any').");

			p0f_context.use_iface = optarg;
			break;
		case 'm':
			if (libp0f_context.max_conn != MAX_CONN || libp0f_context.max_hosts != MAX_HOSTS)
				FATAL("Multiple -m options not supported.");

			if (sscanf(optarg, "%u,%u", &libp0f_context.max_conn, &libp0f_context.max_hosts) != 2 ||
				!libp0f_context.max_conn || libp0f_context.max_conn > 100000 ||
				!libp0f_context.max_hosts || libp0f_context.max_hosts > 500000)
				FATAL("Outlandish value specified for -m.");

			break;
		case 'o':
			if (p0f_context.log_file)
				FATAL("Multiple -o options not supported.");

			p0f_context.log_file = optarg;
			break;
		case 'p':
			if (p0f_context.set_promisc)
				FATAL("Even more promiscuous? People will start talking!");

			p0f_context.set_promisc = 1;
			break;
		case 'r':
			if (libp0f_context.read_file)
				FATAL("Multiple -r options not supported.");
			libp0f_context.read_file = optarg;
			break;
		case 's':
			if (p0f_context.api_sock)
				FATAL("Multiple -s options not supported.");

			p0f_context.api_sock = optarg;
			break;
		case 't':

			if (libp0f_context.conn_max_age != CONN_MAX_AGE || libp0f_context.host_idle_limit != HOST_IDLE_LIMIT)
				FATAL("Multiple -t options not supported.");

			if (sscanf(optarg, "%u,%u", &libp0f_context.conn_max_age, &libp0f_context.host_idle_limit) != 2 ||
				!libp0f_context.conn_max_age || libp0f_context.conn_max_age > 1000000 ||
				!libp0f_context.host_idle_limit || libp0f_context.host_idle_limit > 1000000)
				FATAL("Outlandish value specified for -t.");

			break;
		case 'u':
			if (p0f_context.switch_user)
				FATAL("Split personality mode not supported.");

			p0f_context.switch_user = optarg;
			break;
		default:
			usage();
		}

	if (optind < argc) {

		if (optind + 1 == argc)
			p0f_context.orig_rule = argv[optind];
		else
			FATAL("Filter rule must be a single parameter (use quotes).");
	}

	if (libp0f_context.read_file && p0f_context.api_sock)
		FATAL("API mode looks down on ofline captures.");

	if (!p0f_context.api_sock && p0f_context.api_max_conn != API_MAX_CONN)
		FATAL("Option -S makes sense only with -s.");

	if (p0f_context.daemon_mode) {

		if (libp0f_context.read_file)
			FATAL("Daemon mode and offline captures don't mix.");

		if (!p0f_context.log_file && !p0f_context.api_sock)
			FATAL("Daemon mode requires -o or -s.");

		if (!p0f_context.switch_user)
			SAYF("[!] Consider specifying -u in daemon mode (see README).\n");
	}

	tzset();
	setlocale(LC_TIME, "C");

	close_spare_fds();

	http_init();

	read_config(p0f_context.fp_file ? p0f_context.fp_file : FP_FILE, &libp0f_context);

	prepare_pcap();
	prepare_bpf();

	if (p0f_context.log_file)
		open_log();

	if (p0f_context.api_sock)
		open_api();

	if (p0f_context.daemon_mode) {
		p0f_context.null_fd = open("/dev/null", O_RDONLY);
		if (p0f_context.null_fd < 0) PFATAL("Cannot open '/dev/null'.");
	}

	if (p0f_context.switch_user)
		drop_privs();

	if (p0f_context.daemon_mode)
		fork_off();

	signal(SIGHUP, p0f_context.daemon_mode ? SIG_IGN : abort_handler);
	signal(SIGINT, abort_handler);
	signal(SIGTERM, abort_handler);

	if (libp0f_context.read_file)
		offline_event_loop();
	else
		live_event_loop();

	if (!p0f_context.daemon_mode)
		SAYF("\nAll done. Processed %lu packets.\n", libp0f_context.packet_cnt);

#ifdef DEBUG_BUILD
	destroy_all_hosts();
#endif

	return 0;
}
