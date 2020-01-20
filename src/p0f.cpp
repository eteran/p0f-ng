/*
   p0f - main entry point and all the pcap / unix socket innards
   -------------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <csignal>

#include <dirent.h>
#include <getopt.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <pcap/pcap.h>

#ifdef NET_BPF
#include <net/bpf.h>
#else
#include <pcap-bpf.h>
#endif

#include "p0f/api.h"
#include "p0f/api_client.h"
#include "p0f/config.h"
#include "p0f/debug.h"
#include "p0f/libp0f.h"
#include "p0f/util.h"

#ifndef PF_INET6
#define PF_INET6 10
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

#define LOGF(...) fprintf(lf, __VA_ARGS__)

namespace {

std::string use_iface;           // Interface to listen on
const char *orig_rule = nullptr; // Original filter rule
const char *log_file  = nullptr; // Binary log file name
const char *api_sock  = nullptr; // API socket file name
const char *fp_file   = nullptr; // Location of p0f.fp
const char *read_file = nullptr; // File to read pcap data from

std::unique_ptr<api_client[]> api_cl; // Array with API client state
FILE *lf   = nullptr;                 // Log file stream
pcap_t *pt = nullptr;                 // PCAP capture thingy

int link_type         = 0;            // PCAP link type
uint32_t api_max_conn = API_MAX_CONN; // Maximum number of API connections
int32_t null_fd       = -1;           // File descriptor of /dev/null
int32_t api_fd        = -1;           // API socket descriptor
bool stop_soon        = false;        // Ctrl-C or so pressed?
bool set_promisc      = false;        // Use promiscuous mode?
uint8_t obs_fields    = 0;            // No of pending observation fields
uint8_t daemon_mode   = 0;            // Running in daemon mode?

// Display usage information
[[noreturn]] void usage() {

	constexpr const char message[] =
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

	int32_t closed = 0;
	DIR *d         = opendir("/proc/self/fd");
	if (!d) {
		// Best we could do...
		for (int i = 3; i < 256; i++) {
			if (!close(i)) {
				// TODO(eteran): Why count this, it seems we never output this number from this path
				closed++;
			}
		}
		return;
	}

	while (struct dirent *de = readdir(d)) {
		const int i = atoi(de->d_name);
		if (i > 2 && !close(i)) {
			closed++;
		}
	}

	closedir(d);

	if (closed) {
		SAYF("[+] Closed %u file descriptor%s.\n",
			 closed,
			 closed == 1 ? "" : "s");
	}
}

// Create or open log file
void open_log(const char *filename) {

	int log_fd = open(filename, O_WRONLY | O_APPEND | O_NOFOLLOW | O_LARGEFILE);
	if (log_fd >= 0) {

		struct stat st;
		if (fstat(log_fd, &st)) {
			PFATAL("fstat() on '%s' failed.", filename);
		}

		if (!S_ISREG(st.st_mode)) {
			FATAL("'%s' is not a regular file.", filename);
		}

	} else {
		if (errno != ENOENT) {
			PFATAL("Cannot open '%s'.", filename);
		}

		log_fd = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, LOG_MODE);

		if (log_fd < 0) {
			PFATAL("Cannot open '%s'.", filename);
		}
	}

	if (flock(log_fd, LOCK_EX | LOCK_NB)) {
		FATAL("'%s' is being used by another process.", filename);
	}

	lf = fdopen(log_fd, "a");
	if (!lf) {
		FATAL("fdopen() on '%s' failed.", filename);
	}

	SAYF("[+] Log file '%s' opened for writing.\n", filename);
}

// Create and start listening on API socket
void open_api(const char *socket_name) {

	api_fd = socket(PF_UNIX, SOCK_STREAM, 0);

	if (api_fd < 0) {
		PFATAL("socket(PF_UNIX) failed.");
	}

	struct sockaddr_un u = {};
	u.sun_family         = AF_UNIX;

	if (strlen(socket_name) >= sizeof(u.sun_path)) {
		FATAL("API socket filename is too long for sockaddr_un (blame Unix).");
	}

	strcpy(u.sun_path, socket_name);

	/* This is bad, but you can't do any better with standard unix socket
	 * semantics today :-( */
	struct stat st;
	if (!stat(socket_name, &st) && !S_ISSOCK(st.st_mode)) {
		FATAL("'%s' exists but is not a socket.", socket_name);
	}

	if (unlink(socket_name) && errno != ENOENT) {
		PFATAL("unlink('%s') failed.", socket_name);
	}

	mode_t old_umask = umask(0777 ^ API_MODE);

	if (bind(api_fd, reinterpret_cast<struct sockaddr *>(&u), sizeof(u))) {
		PFATAL("bind() on '%s' failed.", socket_name);
	}

	umask(old_umask);

	if (listen(api_fd, api_max_conn)) {
		PFATAL("listen() on '%s' failed.", socket_name);
	}

	if (fcntl(api_fd, F_SETFL, O_NONBLOCK)) {
		PFATAL("fcntl() to set O_NONBLOCK on API listen socket fails.");
	}

	api_cl = std::make_unique<api_client[]>(api_max_conn);

	for (uint32_t i = 0; i < api_max_conn; i++) {
		api_cl[i].fd = -1;
	}

	SAYF("[+] Listening on API socket '%s' (max %u clients).\n",
		 socket_name,
		 api_max_conn);
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
		while (a && a->addr->sa_family != PF_INET && a->addr->sa_family != PF_INET6) {
			a = a->next;
		}

		if (a) {
			if (a->addr->sa_family == PF_INET) {
				SAYF("     IP address  : %s\n", addr_to_str(reinterpret_cast<const uint8_t *>(a->addr) + 4, IP_VER4));
			} else {
				SAYF("     IP address  : %s\n", addr_to_str(reinterpret_cast<const uint8_t *>(a->addr) + 8, IP_VER6));
			}

		} else {
			SAYF("     IP address  : (none)\n");
		}

	} while ((dev = dev->next));
	SAYF("\n");

	pcap_freealldevs(dev);
}

// Initialize PCAP capture
int prepare_pcap(const char *filename) {

	char pcap_err[PCAP_ERRBUF_SIZE];
	const std::string orig_iface = use_iface;

	if (filename) {
		if (set_promisc) {
			FATAL("Dude, how am I supposed to make a file promiscuous?");
		}

		if (!use_iface.empty()) {
			FATAL("Options -i and -r are mutually exclusive.");
		}

		if (access(filename, R_OK)) {
			PFATAL("Can't access file '%s'.", filename);
		}

		pt = pcap_open_offline(filename, pcap_err);

		if (!pt) {
			FATAL("pcap_open_offline: %s", pcap_err);
		}

		SAYF("[+] Will read pcap data from file '%s'.\n", filename);

	} else {
		if (use_iface.empty()) {
			/* See the earlier note on libpcap SEGV - same problem here.
			 * Also, this returns something stupid on Windows, but hey... */
			if (!access("/sys/class/net", R_OK | X_OK) || errno == ENOENT) {
				pcap_if_t *alldevs = nullptr;
				char error[PCAP_ERRBUF_SIZE];
				if (pcap_findalldevs(&alldevs, error)) {
					FATAL("pcap_findalldevs: %s\n", error);
				}

				use_iface = alldevs->name;
				pcap_freealldevs(alldevs);
			}

			if (use_iface.empty()) {
				FATAL("libpcap is out of ideas; use -i to specify interface.");
			}
		}

		/* PCAP timeouts tend to be broken, so we'll use a very small value
		 * and rely on select() instead. */
		pt = pcap_open_live(use_iface.c_str(), SNAPLEN, set_promisc, 5, pcap_err);

		if (orig_iface.empty()) {
			SAYF("[+] Intercepting traffic on default interface '%s'.\n", use_iface.c_str());
		} else {
			SAYF("[+] Intercepting traffic on interface '%s'.\n", use_iface.c_str());
		}

		if (!pt) {
			FATAL("pcap_open_live: %s", pcap_err);
		}
	}

	return pcap_datalink(pt);
}

// Initialize BPF filtering
void prepare_bpf() {

	struct bpf_program flt = {};

	char final_rule[4096];

	/* VLAN matching is somewhat brain-dead: you need to request it explicitly,
	 * and it alters the semantics of the remainder of the expression. */
	bool vlan_support = (pcap_datalink(pt) == DLT_EN10MB);

retry_no_vlan:

	if (!orig_rule) {
		if (vlan_support) {
			snprintf(final_rule, sizeof(final_rule), "tcp or (vlan and tcp)");
		} else {
			snprintf(final_rule, sizeof(final_rule), "tcp");
		}
	} else {

		if (vlan_support) {
			snprintf(final_rule, sizeof(final_rule), "(tcp and (%s)) or (vlan and tcp and (%s))",
					 orig_rule,
					 orig_rule);

		} else {
			snprintf(final_rule, sizeof(final_rule), "tcp and (%s)",
					 orig_rule);
		}
	}

	DEBUG("[#] Computed rule: %s\n", final_rule);

	if (pcap_compile(pt, &flt, final_rule, 1, 0)) {
		if (vlan_support) {
			vlan_support = false;
			goto retry_no_vlan;
		}

		pcap_perror(pt, "[-] pcap_compile");

		if (!orig_rule) {
			FATAL("pcap_compile() didn't work, strange");
		} else {
			FATAL("Syntax error! See 'man tcpdump' for help on filters.");
		}
	}

	if (pcap_setfilter(pt, &flt)) {
		FATAL("pcap_setfilter() didn't work, strange.");
	}

	pcap_freecode(&flt);

	if (!orig_rule) {
		SAYF("[+] Default packet filtering configured%s.\n",
			 vlan_support ? " [+VLAN]" : "");
	} else {
		SAYF("[+] Custom filtering rule enabled: %s%s\n",
			 orig_rule ? orig_rule : "tcp",
			 vlan_support ? " [+VLAN]" : "");
	}
}

// Drop privileges and chroot(), with some sanity checks
void drop_privs(const char *new_user) {

	struct passwd *const pw = getpwnam(new_user);

	if (!pw) {
		FATAL("User '%s' not found.", new_user);
	}

	if (!strcmp(pw->pw_dir, "/")) {
		FATAL("User '%s' must have a dedicated home directory.", new_user);
	}

	if (!pw->pw_uid || !pw->pw_gid) {
		FATAL("User '%s' must be non-root.", new_user);
	}

	if (initgroups(pw->pw_name, pw->pw_gid)) {
		PFATAL("initgroups() for '%s' failed.", new_user);
	}

	if (chdir(pw->pw_dir)) {
		PFATAL("chdir('%s') failed.", pw->pw_dir);
	}

	if (chroot(pw->pw_dir)) {
		PFATAL("chroot('%s') failed.", pw->pw_dir);
	}

	if (chdir("/")) {
		PFATAL("chdir('/') after chroot('%s') failed.", pw->pw_dir);
	}

	if (!access("/proc/", F_OK) || !access("/sys/", F_OK)) {
		FATAL("User '%s' must have a dedicated home directory.", new_user);
	}

	if (setgid(pw->pw_gid)) {
		PFATAL("setgid(%u) failed.", pw->pw_gid);
	}

	if (setuid(pw->pw_uid)) {
		PFATAL("setuid(%u) failed.", pw->pw_uid);
	}

	if (getegid() != pw->pw_gid || geteuid() != pw->pw_uid) {
		FATAL("Inconsistent euid / egid after dropping privs.");
	}

	SAYF("[+] Privileges dropped: uid %u, gid %u, root '%s'.\n",
		 pw->pw_uid, pw->pw_gid, pw->pw_dir);
}

// Enter daemon mode.
void fork_off() {

	fflush(nullptr);

	switch (pid_t npid = fork()) {
	case -1:
		PFATAL("fork() failed.");
	case 0:
		/* Let's assume all this is fairly unlikely to fail, so we can live
		 * with the parent possibly proclaiming success prematurely. */

		if (dup2(null_fd, 0) < 0) {
			PFATAL("dup2() failed.");
		}

		/* If stderr is redirected to a file, keep that fd and use it for
		 * normal output. */
		if (isatty(2)) {
			if (dup2(null_fd, 1) < 0 || dup2(null_fd, 2) < 0) {
				PFATAL("dup2() failed.");
			}
		} else {
			if (dup2(2, 1) < 0) {
				PFATAL("dup2() failed.");
			}
		}

		close(null_fd);
		null_fd = -1;

		if (chdir("/")) {
			PFATAL("chdir('/') failed.");
		}

		setsid();
		break;
	default:
		SAYF("[+] Daemon process created, PID %u (stderr %s).\n",
			 npid,
			 isatty(2) ? "not kept" : "kept as-is");

		SAYF("\nGood luck, you're on your own now!\n");
		exit(0);
	}
}

// Handler for Ctrl-C and related signals
void abort_handler(int sig) {
	(void)sig;

	if (stop_soon) {
		exit(1);
	}

	stop_soon = true;
}

// Regenerate pollfd data for poll()
uint32_t regen_pfds(const std::unique_ptr<struct pollfd[]> &pfds, const std::unique_ptr<api_client *[]> &ctable) {

	pfds[0].fd     = pcap_fileno(pt);
	pfds[0].events = (POLLIN | POLLERR | POLLHUP);

	DEBUG("[#] Recomputing pollfd data, pcap_fd = %d.\n", pfds[0].fd);

	if (!api_sock) {
		return 1;
	}

	pfds[1].fd     = api_fd;
	pfds[1].events = (POLLIN | POLLERR | POLLHUP);

	uint32_t count = 2;
	for (uint32_t i = 0; i < api_max_conn; i++) {
		if (api_cl[i].fd == -1) {
			continue;
		}

		ctable[count] = &api_cl[i];

		/* If we haven't received a complete query yet, wait for POLLIN.
		 * Otherwise, we want to write stuff. */
		if (api_cl[i].in_off < sizeof(p0f_api_query)) {
			pfds[count].events = (POLLIN | POLLERR | POLLHUP);
		} else {
			pfds[count].events = (POLLOUT | POLLERR | POLLHUP);
		}

		pfds[count++].fd = api_cl[i].fd;
	}

	return count;
}

// Find link-specific offset (pcap knows, but won't tell).
int find_offset(const uint8_t *data, size_t total_len) {

	// Check hardcoded values for some of the most common options.
	switch (link_type) {
	case DLT_RAW:
		return 0;
	case DLT_NULL:
	case DLT_PPP:
		return 4;
	case DLT_LOOP:
#ifdef DLT_PPP_SERIAL
	case DLT_PPP_SERIAL:
#endif // DLT_PPP_SERIAL
	case DLT_PPP_ETHER:
		return 8;
	case DLT_EN10MB:
		return 14;
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		return 16;
#endif // DLT_LINUX_SLL
	case DLT_PFLOG:
		return 28;
	case DLT_IEEE802_11:
		return 32;
	}

	int8_t link_off = -1;

	/* If this fails, try to auto-detect. There is a slight risk that if the
	 * first packet we see is maliciously crafted, and somehow gets past the
	 * configured BPF filter, we will configure the wrong offset. But that
	 * seems fairly unlikely. */
	uint8_t i;
	for (i = 0; i < 40; i += 2, total_len -= 2) {
		if (total_len < MIN_TCP4) {
			break;
		}

		/* Perhaps this is IPv6? We check three things: IP version (first 4 bits);
		 * total length sufficient to accommodate IPv6 and TCP headers; and the
		 * "next protocol" field equal to PROTO_TCP. */
		if (total_len >= MIN_TCP6 && (data[i] >> 4) == IP_VER6) {
			auto hdr = reinterpret_cast<const ipv6_hdr *>(data + i);
			if (hdr->proto == PROTO_TCP) {
				DEBUG("[#] Detected packet offset of %u via IPv6 (link type %u).\n", i, link_type);
				link_off = i;
				break;
			}
		}

		/* Okay, let's try IPv4 then. The same approach, except the shortest
		 * packet size must be just enough to accommodate IPv4 + TCP
		 * (already checked). */
		if ((data[i] >> 4) == IP_VER4) {
			auto hdr = reinterpret_cast<const ipv4_hdr *>(data + i);
			if (hdr->proto == PROTO_TCP) {
				DEBUG("[#] Detected packet offset of %u via IPv4 (link type %u).\n", i, link_type);
				link_off = i;
				break;
			}
		}
	}

	/* If we found something, adjust for VLAN tags (ETH_P_8021Q == 0x8100).
	 * Else, complain once and try again soon. */
	if (link_off >= 4 && data[i - 4] == 0x81 && data[i - 3] == 0x00) {
		DEBUG("[#] Adjusting offset due to VLAN tagging.\n");
		link_off -= 4;
	} else if (link_off == -1) {
		link_off = -2;
		WARN("Unable to find link-specific packet offset. This is bad.");
	}

	return link_off;
}

/* Parse PCAP input, with plenty of sanity checking. Store interesting details
 * in a protocol-agnostic buffer that will be then examined upstream. */
void parse_packet(u_char *user, const pcap_pkthdr *hdr, const u_char *data) {
	auto ctx = reinterpret_cast<libp0f *>(user);

	static int link_off_ = -1;

	// Be paranoid about how much data we actually have off the wire.
	uint32_t packet_len = std::min(hdr->len, hdr->caplen);
	if (packet_len > SNAPLEN) {
		packet_len = SNAPLEN;
	}

	// DEBUG("[#] Received packet: len = %d, caplen = %d, limit = %d\n",
	//    hdr->len, hdr->caplen, SNAPLEN);

	// Account for link-level headers.
	if (link_off_ < 0) {
		link_off_ = find_offset(data, packet_len);
	}

	if (link_off_ > 0) {
		data += link_off_;
		packet_len -= link_off_;
	}

	ctx->parse_packet_frame(hdr->ts, data, packet_len);
}

// Event loop! Accepts and dispatches pcap data, API queries, etc.
void live_event_loop(libp0f *ctx) {

	/* The huge problem with winpcap on cygwin is that you can't get a file
	 * descriptor suitable for poll() / select() out of it:
	 *
	 * http://www.winpcap.org/pipermail/winpcap-users/2009-April/003179.html
	 *
	 * The only alternatives seem to be additional processes / threads, a
	 * nasty busy loop, or a ton of Windows-specific code. If you need API
	 * queries on Windows, you are welcome to fix this :-) */

	// We need room for pcap, and possibly api_fd + api_clients.
	const size_t clients = 1 + (api_sock ? (1 + api_max_conn) : 0);
	auto pfds            = std::make_unique<struct pollfd[]>(clients);
	auto ctable          = std::make_unique<api_client *[]>(clients);

	uint32_t pfd_count = regen_pfds(pfds, ctable);

	if (!daemon_mode) {
		SAYF("[+] Entered main event loop.\n\n");
	}

	while (!stop_soon) {

		/* We had a 250 ms timeout to keep Ctrl-C responsive without resortng
		 * to silly sigaction hackery or unsafe signal handler code.
		 * Unfortunately, if poll() timeout is much longer than pcap timeout,
		 * we end up with dropped packets on VMs. Seems like a kernel bug, but
		 * for now, this loop is a bit busier than it needs to be... */

	poll_again:

		int pret = poll(&pfds[0], pfd_count, 10);
		if (pret < 0) {
			if (errno == EINTR) {
				break;
			}
			PFATAL("poll() failed.");
		}

		if (!pret) {
			if (log_file) {
				fflush(lf);
			}
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
					if (ctable[cur]->in_off < sizeof(p0f_api_query)) {
						FATAL("Inconsistent p0f_api_response state.\n");
					}

					ssize_t i = write(pfds[cur].fd, (&ctable[cur]->out_data) + ctable[cur]->out_off, sizeof(p0f_api_response) - ctable[cur]->out_off);

					if (i <= 0) {
						PFATAL("write() on API socket fails despite POLLOUT.");
					}

					ctable[cur]->out_off += i;

					// All done? Back to square zero then!
					if (ctable[cur]->out_off == sizeof(p0f_api_response)) {

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
					if (pcap_dispatch(pt, -1, parse_packet, reinterpret_cast<u_char *>(ctx)) < 0) {
						FATAL("Packet capture interface is down.");
					}
					break;
				case 1:
					// Accept new API connection, limits permitting.
					if (!api_sock) {
						FATAL("Unexpected API connection.");
					}

					if (pfd_count - 2 < api_max_conn) {
						uint32_t i;
						for (i = 0; i < api_max_conn && api_cl[i].fd >= 0; i++) {
						}

						if (i == api_max_conn) {
							FATAL("Inconsistent API connection data.");
						}

						api_cl[i].fd = accept(api_fd, nullptr, nullptr);

						if (api_cl[i].fd < 0) {
							WARN("Unable to handle API connection: accept() fails.");
						} else {

							if (fcntl(api_cl[i].fd, F_SETFL, O_NONBLOCK)) {
								PFATAL("fcntl() to set O_NONBLOCK on API connection fails.");
							}

							api_cl[i].in_off  = 0;
							api_cl[i].out_off = 0;
							pfd_count         = regen_pfds(pfds, ctable);

							DEBUG("[#] Accepted new API connection, fd %d.\n", api_cl[i].fd);

							goto poll_again;
						}

					} else {
						WARN("Too many API connections (use -S to adjust).\n");
					}

					break;

				default: {
					// Receive API query, dispatch when complete.
					if (ctable[cur]->in_off >= sizeof(p0f_api_query)) {
						FATAL("Inconsistent p0f_api_query state.\n");
					}

					ssize_t i = read(pfds[cur].fd, (&ctable[cur]->in_data) + ctable[cur]->in_off, sizeof(p0f_api_query) - ctable[cur]->in_off);

					if (i < 0) {
						PFATAL("read() on API socket fails despite POLLIN.");
					}

					ctable[cur]->in_off += i;

					// Query in place? Compute response and prepare to send it back.
					if (ctable[cur]->in_off == sizeof(p0f_api_query)) {

						ctx->handle_query(&ctable[cur]->in_data, &ctable[cur]->out_data);
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

	WARN("User-initiated shutdown.");
}

// Simple event loop for processing offline captures.
void offline_event_loop(libp0f *ctx) {

	if (!daemon_mode) {
		SAYF("[+] Processing capture data.\n\n");
	}

	while (!stop_soon) {
		if (pcap_dispatch(pt, -1, parse_packet, reinterpret_cast<u_char *>(ctx)) <= 0) {
			return;
		}
	}

	WARN("User-initiated shutdown.");
}

//
struct libp0f_app : public libp0f {
public:
	libp0f_app(const char *filename)
		: libp0f(filename) {
	}

	libp0f_app(const char *filename, const libp0f_settings &new_settings)
		: libp0f(filename, new_settings) {
	}

public:
	void alert(Alert alert, uint32_t count) override {
		switch (alert) {
		case Alert::TooManyHosts:
			if (!read_file) {
				WARN("Too many host entries, deleting %u. Use -m to adjust.", count);
			}
			break;
		case Alert::TooManyConnections:
			if (!read_file) {
				WARN("Too many tracked connections, deleting %u. Use -m to adjust.",
					 count);
			}
			break;
		}
	}

public:
	// Open log entry.
	void start_observation(time_t time, const char *keyword, uint8_t field_cnt, bool to_srv, const packet_flow *f) override {

		if (obs_fields) {
			FATAL("Premature end of observation.");
		}

		if (!daemon_mode) {
			SAYF(".-[ %s/%u -> ",
				 addr_to_str(f->client->addr, f->client->ip_ver),
				 f->cli_port);

			SAYF("%s/%u (%s) ]-\n|\n",
				 addr_to_str(f->server->addr, f->client->ip_ver),
				 f->srv_port,
				 keyword);

			SAYF("| %-8s = %s/%u\n", to_srv ? "client" : "server",
				 addr_to_str(to_srv ? f->client->addr : f->server->addr, f->client->ip_ver),
				 to_srv ? f->cli_port : f->srv_port);
		}

		if (log_file) {
			char tmp[64];
			strftime(tmp, sizeof(tmp), "%Y/%m/%d %H:%M:%S", localtime(&time));

			LOGF("[%s] mod=%s|cli=%s/%u|",
				 tmp,
				 keyword,
				 addr_to_str(f->client->addr, f->client->ip_ver),
				 f->cli_port);

			LOGF("srv=%s/%u|subj=%s",
				 addr_to_str(f->server->addr, f->server->ip_ver),
				 f->srv_port,
				 to_srv ? "cli" : "srv");
		}

		obs_fields = field_cnt;
	}

	// Add log item.
	void observation_field(const char *key, const char *value) override {

		if (!obs_fields) {
			FATAL("Unexpected observation field ('%s').", key);
		}

		if (!daemon_mode) {
			SAYF("| %-8s = %s\n", key, value ? value : "???");
		}

		if (log_file) {
			LOGF("|%s=%s", key, value ? value : "???");
		}

		obs_fields--;

		if (!obs_fields) {
			if (!daemon_mode) {
				SAYF("|\n`----\n\n");
			}

			if (log_file) {
				LOGF("\n");
			}
		}
	}
};

}

// Main entry point
int main(int argc, char *argv[]) {

	libp0f_settings p0f_settings;

	setlinebuf(stdout);

	SAYF("--- p0f %s by Michal Zalewski <lcamtuf@coredump.cx> ---\n\n", VERSION);

	if (getuid() != geteuid()) {
		FATAL("Please don't make me setuid. See README for more.\n");
	}

	const char *switch_user = nullptr; // Target username

	int r;
	while ((r = getopt(argc, argv, "+LS:df:i:m:o:pr:s:t:u:")) != -1) {
		switch (r) {
		case 'L':
			list_interfaces();
			exit(0);
		case 'S':
			if (api_max_conn != API_MAX_CONN) {
				FATAL("Multiple -S options not supported.");
			}

			api_max_conn = atoi(optarg);

			if (!api_max_conn || api_max_conn > 100) {
				FATAL("Outlandish value specified for -S.");
			}

			break;
		case 'd':
			if (daemon_mode) {
				FATAL("Double werewolf mode not supported yet.");
			}

			daemon_mode = 1;
			break;
		case 'f':
			if (fp_file) {
				FATAL("Multiple -f options not supported.");
			}

			fp_file = optarg;
			break;
		case 'i':
			if (!use_iface.empty()) {
				FATAL("Multiple -i options not supported (try '-i any').");
			}

			use_iface = optarg;
			break;
		case 'm':
			if (p0f_settings.max_conn != MAX_CONN || p0f_settings.max_hosts != MAX_HOSTS) {
				FATAL("Multiple -m options not supported.");
			}

			if (sscanf(optarg, "%u,%u", &p0f_settings.max_conn, &p0f_settings.max_hosts) != 2 ||
				!p0f_settings.max_conn || p0f_settings.max_conn > 100000 ||
				!p0f_settings.max_hosts || p0f_settings.max_hosts > 500000) {
				FATAL("Outlandish value specified for -m.");
			}

			break;
		case 'o':
			if (log_file) {
				FATAL("Multiple -o options not supported.");
			}

			log_file = optarg;
			break;
		case 'p':
			if (set_promisc) {
				FATAL("Even more promiscuous? People will start talking!");
			}

			set_promisc = true;
			break;
		case 'r':
			if (read_file) {
				FATAL("Multiple -r options not supported.");
			}
			read_file = optarg;
			break;
		case 's':
			if (api_sock) {
				FATAL("Multiple -s options not supported.");
			}

			api_sock = optarg;
			break;
		case 't':

			if (p0f_settings.conn_max_age != CONN_MAX_AGE || p0f_settings.host_idle_limit != HOST_IDLE_LIMIT) {
				FATAL("Multiple -t options not supported.");
			}

			if (sscanf(optarg, "%u,%u", &p0f_settings.conn_max_age, &p0f_settings.host_idle_limit) != 2 || !p0f_settings.conn_max_age || p0f_settings.conn_max_age > 1000000 || !p0f_settings.host_idle_limit || p0f_settings.host_idle_limit > 1000000) {
				FATAL("Outlandish value specified for -t.");
			}

			break;
		case 'u':
			if (switch_user) {
				FATAL("Split personality mode not supported.");
			}

			switch_user = optarg;
			break;
		default:
			usage();
		}
	}

	if (optind < argc) {
		if (optind + 1 == argc) {
			orig_rule = argv[optind];
		} else {
			FATAL("Filter rule must be a single parameter (use quotes).");
		}
	}

	if (read_file && api_sock) {
		FATAL("API mode looks down on ofline captures.");
	}

	if (!api_sock && api_max_conn != API_MAX_CONN) {
		FATAL("Option -S makes sense only with -s.");
	}

	if (daemon_mode) {

		if (read_file) {
			FATAL("Daemon mode and offline captures don't mix.");
		}

		if (!log_file && !api_sock) {
			FATAL("Daemon mode requires -o or -s.");
		}

		if (!switch_user) {
			SAYF("[!] Consider specifying -u in daemon mode (see README).\n");
		}
	}

	tzset();
	setlocale(LC_TIME, "C");

	close_spare_fds();

	// Initialize the p0f library
	libp0f_app p0f(fp_file, p0f_settings);

	link_type = prepare_pcap(read_file);
	prepare_bpf();

	if (log_file) {
		open_log(log_file);
	}

	if (api_sock) {
		open_api(api_sock);
	}

	if (daemon_mode) {
		null_fd = open("/dev/null", O_RDONLY);
		if (null_fd < 0) {
			PFATAL("Cannot open '/dev/null'.");
		}
	}

	if (switch_user) {
		drop_privs(switch_user);
	}

	if (daemon_mode) {
		fork_off();
	}

	signal(SIGHUP, daemon_mode ? SIG_IGN : abort_handler);
	signal(SIGINT, abort_handler);
	signal(SIGTERM, abort_handler);

	if (read_file) {
		offline_event_loop(&p0f);
	} else {
		live_event_loop(&p0f);
	}

	if (!daemon_mode) {
		SAYF("\nAll done. Processed %lu packets.\n", p0f.packet_cnt);
	}
}
