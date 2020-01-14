/*
   p0f - main entry point and all the pcap / unix socket innards
   -------------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

//#define _GNU_SOURCE
#define _FROM_P0F

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <locale.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
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
#endif /* !NET_BPF */

#include "alloc-inl.h"
#include "api.h"
#include "debug.h"
#include "fp_http.h"
#include "p0f.h"
#include "process.h"
#include "readfp.h"
#include "tcp.h"
#include "types.h"

#ifndef PF_INET6
#define PF_INET6 10
#endif /* !PF_INET6 */

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif /* !O_NOFOLLOW */

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif /* !O_LARGEFILE */

struct p0f_context_t {
	uint8_t *use_iface        = nullptr;      /* Interface to listen on             */
	uint8_t *orig_rule        = nullptr;      /* Original filter rule               */
	uint8_t *switch_user      = nullptr;      /* Target username                    */
	uint8_t *log_file         = nullptr;      /* Binary log file name               */
	uint8_t *api_sock         = nullptr;      /* API socket file name               */
	uint8_t *fp_file          = nullptr;      /* Location of p0f.fp                 */
	uint32_t api_max_conn     = API_MAX_CONN; /* Maximum number of API connections  */
	struct api_client *api_cl = nullptr;      /* Array with API client state        */

	int32_t null_fd = -1; /* File descriptor of /dev/null       */
	int32_t api_fd  = -1; /* API socket descriptor              */

	FILE *lf = nullptr; /* Log file stream                    */

	uint8_t stop_soon = 0; /* Ctrl-C or so pressed?              */
};

static p0f_context_t p0f_context;

uint8_t *read_file; /* File to read pcap data from        */

uint32_t max_conn        = MAX_CONN;        /* Connection entry count limit       */
uint32_t max_hosts       = MAX_HOSTS;       /* Host cache entry count limit       */
uint32_t conn_max_age    = CONN_MAX_AGE;    /* Maximum age of a connection entry  */
uint32_t host_idle_limit = HOST_IDLE_LIMIT; /* Host cache idle timeout            */

uint8_t daemon_mode; /* Running in daemon mode?            */

static uint8_t set_promisc; /* Use promiscuous mode?              */

static pcap_t *pt; /* PCAP capture thingy                */

int32_t link_type; /* PCAP link type                     */

static uint8_t obs_fields; /* No of pending observation fields   */

#define LOGF(...) fprintf(p0f_context.lf, __VA_ARGS__)

/* Display usage information */

static void usage() {

	ERRORF(

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
#ifndef __CYGWIN__
		"  -s name   - answer to API queries at a named unix socket\n"
#endif /* !__CYGWIN__ */
		"  -u user   - switch to the specified unprivileged account and chroot\n"
		"  -d        - fork into background (requires -o or -s)\n"
		"\n"
		"Performance-related options:\n"
		"\n"
#ifndef __CYGWIN__
		"  -S limit  - limit number of parallel API connections (%u)\n"
#endif /* !__CYGWIN__ */
		"  -t c,h    - set connection / host cache age limits (%us,%um)\n"
		"  -m c,h    - cap the number of active connections / hosts (%u,%u)\n"
		"\n"
		"Optional filter expressions (man tcpdump) can be specified in the command\n"
		"line to prevent p0f from looking at incidental network traffic.\n"
		"\n"
		"Problems? You can reach the author at <lcamtuf@coredump.cx>.\n",

		FP_FILE,
#ifndef __CYGWIN__
		API_MAX_CONN,
#endif /* !__CYGWIN__ */
		CONN_MAX_AGE, HOST_IDLE_LIMIT, MAX_CONN, MAX_HOSTS);

	exit(1);
}

/* Get rid of unnecessary file descriptors */
static void close_spare_fds() {

	int32_t i, closed = 0;
	DIR *d;
	struct dirent *de;

	d = opendir("/proc/self/fd");

	if (!d) {
		/* Best we could do... */
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

/* Create or open log file */

static void open_log() {

	struct stat st;
	int32_t log_fd;

	log_fd = open((char *)p0f_context.log_file, O_WRONLY | O_APPEND | O_NOFOLLOW | O_LARGEFILE);

	if (log_fd >= 0) {

		if (fstat(log_fd, &st)) PFATAL("fstat() on '%s' failed.", p0f_context.log_file);

		if (!S_ISREG(st.st_mode)) FATAL("'%s' is not a regular file.", p0f_context.log_file);

	} else {

		if (errno != ENOENT) PFATAL("Cannot open '%s'.", p0f_context.log_file);

		log_fd = open((char *)p0f_context.log_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
					  LOG_MODE);

		if (log_fd < 0) PFATAL("Cannot open '%s'.", p0f_context.log_file);
	}

	if (flock(log_fd, LOCK_EX | LOCK_NB))
		FATAL("'%s' is being used by another process.", p0f_context.log_file);

	p0f_context.lf = fdopen(log_fd, "a");

	if (!p0f_context.lf) FATAL("fdopen() on '%s' failed.", p0f_context.log_file);

	SAYF("[+] Log file '%s' opened for writing.\n", p0f_context.log_file);
}

/* Create and start listening on API socket */

static void open_api() {

	int32_t old_umask;
	uint32_t i;

	struct sockaddr_un u;
	struct stat st;

	p0f_context.api_fd = socket(PF_UNIX, SOCK_STREAM, 0);

	if (p0f_context.api_fd < 0) PFATAL("socket(PF_UNIX) failed.");

	memset(&u, 0, sizeof(u));
	u.sun_family = AF_UNIX;

	if (strlen((char *)p0f_context.api_sock) >= sizeof(u.sun_path))
		FATAL("API socket filename is too long for sockaddr_un (blame Unix).");

	strcpy(u.sun_path, (char *)p0f_context.api_sock);

	/* This is bad, but you can't do any better with standard unix socket
     semantics today :-( */

	if (!stat((char *)p0f_context.api_sock, &st) && !S_ISSOCK(st.st_mode))
		FATAL("'%s' exists but is not a socket.", p0f_context.api_sock);

	if (unlink((char *)p0f_context.api_sock) && errno != ENOENT)
		PFATAL("unlink('%s') failed.", p0f_context.api_sock);

	old_umask = umask(0777 ^ API_MODE);

	if (bind(p0f_context.api_fd, (struct sockaddr *)&u, sizeof(u)))
		PFATAL("bind() on '%s' failed.", p0f_context.api_sock);

	umask(old_umask);

	if (listen(p0f_context.api_fd, p0f_context.api_max_conn))
		PFATAL("listen() on '%s' failed.", p0f_context.api_sock);

	if (fcntl(p0f_context.api_fd, F_SETFL, O_NONBLOCK))
		PFATAL("fcntl() to set O_NONBLOCK on API listen socket fails.");

	p0f_context.api_cl = (struct api_client *)calloc(p0f_context.api_max_conn, sizeof(struct api_client));

	for (i = 0; i < p0f_context.api_max_conn; i++)
		p0f_context.api_cl[i].fd = -1;

	SAYF("[+] Listening on API socket '%s' (max %u clients).\n",
		 p0f_context.api_sock, p0f_context.api_max_conn);
}

/* Open log entry. */

void start_observation(const char *keyword, uint8_t field_cnt, uint8_t to_srv, const struct packet_flow *f) {

	if (obs_fields) FATAL("Premature end of observation.");

	if (!daemon_mode) {

		SAYF(".-[ %s/%u -> ", addr_to_str(f->client->addr, f->client->ip_ver),
			 f->cli_port);
		SAYF("%s/%u (%s) ]-\n|\n", addr_to_str(f->server->addr, f->client->ip_ver),
			 f->srv_port, keyword);

		SAYF("| %-8s = %s/%u\n", to_srv ? "client" : "server",
			 addr_to_str(to_srv ? f->client->addr : f->server->addr, f->client->ip_ver),
			 to_srv ? f->cli_port : f->srv_port);
	}

	if (p0f_context.log_file) {

		uint8_t tmp[64];

		time_t ut     = get_unix_time();
		struct tm *lt = localtime(&ut);

		strftime((char *)tmp, 64, "%Y/%m/%d %H:%M:%S", lt);

		LOGF("[%s] mod=%s|cli=%s/%u|", tmp, keyword, addr_to_str(f->client->addr, f->client->ip_ver), f->cli_port);

		LOGF("srv=%s/%u|subj=%s", addr_to_str(f->server->addr, f->server->ip_ver),
			 f->srv_port, to_srv ? "cli" : "srv");
	}

	obs_fields = field_cnt;
}

/* Add log item. */

void add_observation_field(const char *key, const uint8_t *value) {

	if (!obs_fields) FATAL("Unexpected observation field ('%s').", key);

	if (!daemon_mode)
		SAYF("| %-8s = %s\n", key, value ? value : (const uint8_t *)"???");

	if (p0f_context.log_file) LOGF("|%s=%s", key, value ? value : (const uint8_t *)"???");

	obs_fields--;

	if (!obs_fields) {

		if (!daemon_mode) SAYF("|\n`----\n\n");

		if (p0f_context.log_file) LOGF("\n");
	}
}

/* Show PCAP interface list */

static void list_interfaces() {

	char pcap_err[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev;
	uint8_t i = 0;

	/* There is a bug in several years' worth of libpcap releases that causes it
     to SEGV here if /sys/class/net is not readable. See http://goo.gl/nEnGx */

	if (access("/sys/class/net", R_OK | X_OK) && errno != ENOENT)
		FATAL("This operation requires access to /sys/class/net/, sorry.");

	if (pcap_findalldevs(&dev, pcap_err) == -1)
		FATAL("pcap_findalldevs: %s\n", pcap_err);

	if (!dev) FATAL("Can't find any interfaces. Maybe you need to be root?");

	SAYF("\n-- Available interfaces --\n");

	do {

		pcap_addr_t *a = dev->addresses;

		SAYF("\n%3d: Name        : %s\n", i++, dev->name);
		SAYF("     Description : %s\n", dev->description ? dev->description : "-");

		/* Let's try to find something we can actually display. */

		while (a && a->addr->sa_family != PF_INET && a->addr->sa_family != PF_INET6)
			a = a->next;

		if (a) {

			if (a->addr->sa_family == PF_INET)
				SAYF("     IP address  : %s\n", addr_to_str(((uint8_t *)a->addr) + 4, IP_VER4));
			else
				SAYF("     IP address  : %s\n", addr_to_str(((uint8_t *)a->addr) + 8, IP_VER6));

		} else
			SAYF("     IP address  : (none)\n");

	} while ((dev = dev->next));

	SAYF("\n");

	pcap_freealldevs(dev);
}

#ifdef __CYGWIN__

/* List PCAP-recognized interfaces */

static uint8_t *find_interface(int num) {

	char pcap_err[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev;

	if (pcap_findalldevs(&dev, pcap_err) == -1)
		FATAL("pcap_findalldevs: %s\n", pcap_err);

	do {

		if (!num--) {
			uint8_t *ret = ck_strdup((char *)dev->name);
			pcap_freealldevs(dev);
			return ret;
		}

	} while ((dev = dev->next));

	FATAL("Interface not found (use -L to list all).");
}

#endif /* __CYGWIN__ */

/* Initialize PCAP capture */

static void prepare_pcap() {

	char pcap_err[PCAP_ERRBUF_SIZE];
	uint8_t *orig_iface = p0f_context.use_iface;

	if (read_file) {

		if (set_promisc)
			FATAL("Dude, how am I supposed to make a file promiscuous?");

		if (p0f_context.use_iface)
			FATAL("Options -i and -r are mutually exclusive.");

		if (access((char *)read_file, R_OK))
			PFATAL("Can't access file '%s'.", read_file);

		pt = pcap_open_offline((char *)read_file, pcap_err);

		if (!pt) FATAL("pcap_open_offline: %s", pcap_err);

		SAYF("[+] Will read pcap data from file '%s'.\n", read_file);

	} else {

		if (!p0f_context.use_iface) {

			/* See the earlier note on libpcap SEGV - same problem here.
         Also, this returns something stupid on Windows, but hey... */

			if (!access("/sys/class/net", R_OK | X_OK) || errno == ENOENT)
				p0f_context.use_iface = (uint8_t *)pcap_lookupdev(pcap_err);

			if (!p0f_context.use_iface)
				FATAL("libpcap is out of ideas; use -i to specify interface.");

		}

#ifdef __CYGWIN__

		/* On Windows, interface names are unwieldy, and people prefer to use
       numerical IDs. */

		else {

			int iface_id;

			if (sscanf((char *)use_iface, "%u", &iface_id) == 1) {
				use_iface = find_interface(iface_id);
			}
		}

		pt = pcap_open_live((char *)use_iface, SNAPLEN, set_promisc, 250, pcap_err);

#else

		/* PCAP timeouts tend to be broken, so we'll use a very small value
       and rely on select() instead. */

		pt = pcap_open_live((char *)p0f_context.use_iface, SNAPLEN, set_promisc, 5, pcap_err);

#endif /* ^__CYGWIN__ */

		if (!orig_iface)
			SAYF("[+] Intercepting traffic on default interface '%s'.\n", p0f_context.use_iface);
		else
			SAYF("[+] Intercepting traffic on interface '%s'.\n", p0f_context.use_iface);

		if (!pt) FATAL("pcap_open_live: %s", pcap_err);
	}

	link_type = pcap_datalink(pt);
}

/* Initialize BPF filtering */

static void prepare_bpf() {

	struct bpf_program flt;
	memset(&flt, 0, sizeof(flt));

	uint8_t *final_rule  = nullptr;
	uint8_t vlan_support = 0;

	/* VLAN matching is somewhat brain-dead: you need to request it explicitly,
     and it alters the semantics of the remainder of the expression. */

	vlan_support = (pcap_datalink(pt) == DLT_EN10MB);

retry_no_vlan:

	if (!p0f_context.orig_rule) {

		if (vlan_support) {
			final_rule = (uint8_t *)"tcp or (vlan and tcp)";
		} else {
			final_rule = (uint8_t *)"tcp";
		}

	} else {

		if (vlan_support) {

			final_rule = (uint8_t *)calloc(strlen((char *)p0f_context.orig_rule) * 2 + 64, 1);

			sprintf((char *)final_rule, "(tcp and (%s)) or (vlan and tcp and (%s))",
					p0f_context.orig_rule, p0f_context.orig_rule);

		} else {

			final_rule = (uint8_t *)calloc(strlen((char *)p0f_context.orig_rule) + 16, 1);

			sprintf((char *)final_rule, "tcp and (%s)", p0f_context.orig_rule);
		}
	}

	DEBUG("[#] Computed rule: %s\n", final_rule);

	if (pcap_compile(pt, &flt, (char *)final_rule, 1, 0)) {

		if (vlan_support) {

			if (p0f_context.orig_rule) free(final_rule);
			vlan_support = 0;
			goto retry_no_vlan;
		}

		pcap_perror(pt, "[-] pcap_compile");

		if (!p0f_context.orig_rule)
			FATAL("pcap_compile() didn't work, strange");
		else
			FATAL("Syntax error! See 'man tcpdump' for help on filters.");
	}

	if (pcap_setfilter(pt, &flt))
		FATAL("pcap_setfilter() didn't work, strange.");

	pcap_freecode(&flt);

	if (!p0f_context.orig_rule) {

		SAYF("[+] Default packet filtering configured%s.\n",
			 vlan_support ? " [+VLAN]" : "");

	} else {

		SAYF("[+] Custom filtering rule enabled: %s%s\n",
			 p0f_context.orig_rule ? p0f_context.orig_rule : (uint8_t *)"tcp",
			 vlan_support ? " [+VLAN]" : "");

		free(final_rule);
	}
}

/* Drop privileges and chroot(), with some sanity checks */

static void drop_privs() {

	struct passwd *pw = getpwnam((char *)p0f_context.switch_user);

	if (!pw) FATAL("User '%s' not found.", p0f_context.switch_user);

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

/* Enter daemon mode. */

static void fork_off() {

	int32_t npid;

	fflush(0);

	npid = fork();

	if (npid < 0) PFATAL("fork() failed.");

	if (!npid) {

		/* Let's assume all this is fairly unlikely to fail, so we can live
       with the parent possibly proclaiming success prematurely. */

		if (dup2(p0f_context.null_fd, 0) < 0) PFATAL("dup2() failed.");

		/* If stderr is redirected to a file, keep that fd and use it for
       normal output. */

		if (isatty(2)) {

			if (dup2(p0f_context.null_fd, 1) < 0 || dup2(p0f_context.null_fd, 2) < 0)
				PFATAL("dup2() failed.");

		} else {

			if (dup2(2, 1) < 0) PFATAL("dup2() failed.");
		}

		close(p0f_context.null_fd);
		p0f_context.null_fd = -1;

		if (chdir("/")) PFATAL("chdir('/') failed.");

		setsid();

	} else {

		SAYF("[+] Daemon process created, PID %u (stderr %s).\n", npid,
			 isatty(2) ? "not kept" : "kept as-is");

		SAYF("\nGood luck, you're on your own now!\n");

		exit(0);
	}
}

/* Handler for Ctrl-C and related signals */

static void abort_handler(int sig) {
	(void)sig;
	if (p0f_context.stop_soon) exit(1);
	p0f_context.stop_soon = 1;
}

#ifndef __CYGWIN__

/* Regenerate pollfd data for poll() */

static uint32_t regen_pfds(struct pollfd *pfds, struct api_client **ctable) {
	uint32_t i, count = 2;

	pfds[0].fd     = pcap_fileno(pt);
	pfds[0].events = (POLLIN | POLLERR | POLLHUP);

	DEBUG("[#] Recomputing pollfd data, pcap_fd = %d.\n", pfds[0].fd);

	if (!p0f_context.api_sock) return 1;

	pfds[1].fd     = p0f_context.api_fd;
	pfds[1].events = (POLLIN | POLLERR | POLLHUP);

	for (i = 0; i < p0f_context.api_max_conn; i++) {

		if (p0f_context.api_cl[i].fd == -1) continue;

		ctable[count] = p0f_context.api_cl + i;

		/* If we haven't received a complete query yet, wait for POLLIN.
       Otherwise, we want to write stuff. */

		if (p0f_context.api_cl[i].in_off < sizeof(struct p0f_api_query))
			pfds[count].events = (POLLIN | POLLERR | POLLHUP);
		else
			pfds[count].events = (POLLOUT | POLLERR | POLLHUP);

		pfds[count++].fd = p0f_context.api_cl[i].fd;
	}

	return count;
}

#endif /* !__CYGWIN__ */

/* Event loop! Accepts and dispatches pcap data, API queries, etc. */

static void live_event_loop() {

#ifndef __CYGWIN__

	/* The huge problem with winpcap on cygwin is that you can't get a file
     descriptor suitable for poll() / select() out of it:

     http://www.winpcap.org/pipermail/winpcap-users/2009-April/003179.html

     The only alternatives seem to be additional processes / threads, a
     nasty busy loop, or a ton of Windows-specific code. If you need APi
     queries on Windows, you are welcome to fix this :-) */

	/* We need room for pcap, and possibly p0f_context.api_fd + api_clients. */
	auto pfds   = (struct pollfd *)calloc((1 + (p0f_context.api_sock ? (1 + p0f_context.api_max_conn) : 0)), sizeof(struct pollfd));
	auto ctable = (struct api_client **)calloc((1 + (p0f_context.api_sock ? (1 + p0f_context.api_max_conn) : 0)), sizeof(struct api_client *));

	uint32_t pfd_count = regen_pfds(pfds, ctable);

	if (!daemon_mode)
		SAYF("[+] Entered main event loop.\n\n");

	while (!p0f_context.stop_soon) {

		int32_t pret, i;
		uint32_t cur;

		/* We had a 250 ms timeout to keep Ctrl-C responsive without resortng
       to silly sigaction hackery or unsafe signal handler code. Unfortunately,
       if poll() timeout is much longer than pcap timeout, we end up with
       dropped packets on VMs. Seems like a kernel bug, but for now, this
       loop is a bit busier than it needs to be... */

	poll_again:

		pret = poll(pfds, pfd_count, 10);

		if (pret < 0) {
			if (errno == EINTR) break;
			PFATAL("poll() failed.");
		}

		if (!pret) {
			if (p0f_context.log_file)
				fflush(p0f_context.lf);
			continue;
		}

		/* Examine pfds... */

		for (cur = 0; cur < pfd_count; cur++) {
			if (pfds[cur].revents & (POLLERR | POLLHUP)) switch (cur) {
				case 0:
					FATAL("Packet capture interface is down.");
				case 1:
					FATAL("API socket is down.");
				default:
					/* Shut down API connection and free its state. */
					DEBUG("[#] API connection on fd %d closed.\n", pfds[cur].fd);

					close(pfds[cur].fd);
					ctable[cur]->fd = -1;

					pfd_count = regen_pfds(pfds, ctable);
					goto poll_again;
				}

			if (pfds[cur].revents & POLLOUT) switch (cur) {

				case 0:
				case 1:

					FATAL("Unexpected POLLOUT on fd %d.\n", cur);

				default:

					/* Write API response, restart state when complete. */

					if (ctable[cur]->in_off < sizeof(struct p0f_api_query))
						FATAL("Inconsistent p0f_api_response state.\n");

					i = write(pfds[cur].fd,
							  ((char *)&ctable[cur]->out_data) + ctable[cur]->out_off,
							  sizeof(struct p0f_api_response) - ctable[cur]->out_off);

					if (i <= 0) PFATAL("write() on API socket fails despite POLLOUT.");

					ctable[cur]->out_off += i;

					/* All done? Back to square zero then! */

					if (ctable[cur]->out_off == sizeof(struct p0f_api_response)) {

						ctable[cur]->in_off = ctable[cur]->out_off = 0;
						pfds[cur].events                           = (POLLIN | POLLERR | POLLHUP);
					}
				}

			if (pfds[cur].revents & POLLIN) switch (cur) {

				case 0:

					/* Process traffic on the capture interface. */

					if (pcap_dispatch(pt, -1, (pcap_handler)parse_packet, 0) < 0)
						FATAL("Packet capture interface is down.");

					break;

				case 1:

					/* Accept new API connection, limits permitting. */

					if (!p0f_context.api_sock) FATAL("Unexpected API connection.");

					if (pfd_count - 2 < p0f_context.api_max_conn) {

						for (i = 0; i < p0f_context.api_max_conn && p0f_context.api_cl[i].fd >= 0; i++)
							;

						if (i == p0f_context.api_max_conn) FATAL("Inconsistent API connection data.");

						p0f_context.api_cl[i].fd = accept(p0f_context.api_fd, nullptr, nullptr);

						if (p0f_context.api_cl[i].fd < 0) {

							WARN("Unable to handle API connection: accept() fails.");

						} else {

							if (fcntl(p0f_context.api_cl[i].fd, F_SETFL, O_NONBLOCK))
								PFATAL("fcntl() to set O_NONBLOCK on API connection fails.");

							p0f_context.api_cl[i].in_off = p0f_context.api_cl[i].out_off = 0;
							pfd_count                                                    = regen_pfds(pfds, ctable);

							DEBUG("[#] Accepted new API connection, fd %d.\n", p0f_context.api_cl[i].fd);

							goto poll_again;
						}

					} else
						WARN("Too many API connections (use -S to adjust).\n");

					break;

				default:

					/* Receive API query, dispatch when complete. */

					if (ctable[cur]->in_off >= sizeof(struct p0f_api_query))
						FATAL("Inconsistent p0f_api_query state.\n");

					i = read(pfds[cur].fd,
							 ((char *)&ctable[cur]->in_data) + ctable[cur]->in_off,
							 sizeof(struct p0f_api_query) - ctable[cur]->in_off);

					if (i < 0) PFATAL("read() on API socket fails despite POLLIN.");

					ctable[cur]->in_off += i;

					/* Query in place? Compute response and prepare to send it back. */

					if (ctable[cur]->in_off == sizeof(struct p0f_api_query)) {

						handle_query(&ctable[cur]->in_data, &ctable[cur]->out_data);
						pfds[cur].events = (POLLOUT | POLLERR | POLLHUP);
					}
				}

			/* Processed all reported updates already? If so, bail out early. */

			if (pfds[cur].revents && !--pret) break;
		}
	}

	free(ctable);
	free(pfds);

#else

	if (!daemon_mode)
		SAYF("[+] Entered main event loop.\n\n");

	/* Ugh. The only way to keep SIGINT and other signals working is to have this
     funny loop with dummy I/O every 250 ms. Signal handlers don't get called
     in pcap_dispatch() or pcap_loop() unless there's I/O. */

	while (!stop_soon) {

		int32_t ret = pcap_dispatch(pt, -1, (pcap_handler)parse_packet, 0);

		if (ret < 0) return;

		if (log_file && !ret) fflush(lf);

		write(2, nullptr, 0);
	}

#endif /* ^!__CYGWIN__ */

	WARN("User-initiated shutdown.");
}

/* Simple event loop for processing offline captures. */

static void offline_event_loop() {

	if (!daemon_mode)
		SAYF("[+] Processing capture data.\n\n");

	while (!p0f_context.stop_soon) {
		if (pcap_dispatch(pt, -1, (pcap_handler)parse_packet, nullptr) <= 0) {
			return;
		}
	}

	WARN("User-initiated shutdown.");
}

/* Main entry point */

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
#ifdef __CYGWIN__
			FATAL("API mode not supported on Windows (see README).");
#else
			if (p0f_context.api_max_conn != API_MAX_CONN)
				FATAL("Multiple -S options not supported.");

			p0f_context.api_max_conn = atol(optarg);

			if (!p0f_context.api_max_conn || p0f_context.api_max_conn > 100)
				FATAL("Outlandish value specified for -S.");

			break;
#endif /* ^__CYGWIN__ */

		case 'd':

			if (daemon_mode)
				FATAL("Double werewolf mode not supported yet.");

			daemon_mode = 1;
			break;

		case 'f':

			if (p0f_context.fp_file)
				FATAL("Multiple -f options not supported.");

			p0f_context.fp_file = (uint8_t *)optarg;
			break;

		case 'i':

			if (p0f_context.use_iface)
				FATAL("Multiple -i options not supported (try '-i any').");

			p0f_context.use_iface = (uint8_t *)optarg;

			break;

		case 'm':

			if (max_conn != MAX_CONN || max_hosts != MAX_HOSTS)
				FATAL("Multiple -m options not supported.");

			if (sscanf(optarg, "%u,%u", &max_conn, &max_hosts) != 2 ||
				!max_conn || max_conn > 100000 ||
				!max_hosts || max_hosts > 500000)
				FATAL("Outlandish value specified for -m.");

			break;

		case 'o':
			if (p0f_context.log_file)
				FATAL("Multiple -o options not supported.");

			p0f_context.log_file = (uint8_t *)optarg;

			break;

		case 'p':
			if (set_promisc)
				FATAL("Even more promiscuous? People will start talking!");

			set_promisc = 1;
			break;

		case 'r':

			if (read_file)
				FATAL("Multiple -r options not supported.");

			read_file = (uint8_t *)optarg;

			break;

		case 's':

#ifdef __CYGWIN__

			FATAL("API mode not supported on Windows (see README).");

#else

			if (p0f_context.api_sock)
				FATAL("Multiple -s options not supported.");

			p0f_context.api_sock = (uint8_t *)optarg;

			break;

#endif /* ^__CYGWIN__ */

		case 't':

			if (conn_max_age != CONN_MAX_AGE || host_idle_limit != HOST_IDLE_LIMIT)
				FATAL("Multiple -t options not supported.");

			if (sscanf(optarg, "%u,%u", &conn_max_age, &host_idle_limit) != 2 ||
				!conn_max_age || conn_max_age > 1000000 ||
				!host_idle_limit || host_idle_limit > 1000000)
				FATAL("Outlandish value specified for -t.");

			break;

		case 'u':

			if (p0f_context.switch_user)
				FATAL("Split personality mode not supported.");

			p0f_context.switch_user = (uint8_t *)optarg;

			break;

		default:
			usage();
		}

	if (optind < argc) {

		if (optind + 1 == argc)
			p0f_context.orig_rule = (uint8_t *)argv[optind];
		else
			FATAL("Filter rule must be a single parameter (use quotes).");
	}

	if (read_file && p0f_context.api_sock)
		FATAL("API mode looks down on ofline captures.");

	if (!p0f_context.api_sock && p0f_context.api_max_conn != API_MAX_CONN)
		FATAL("Option -S makes sense only with -s.");

	if (daemon_mode) {

		if (read_file)
			FATAL("Daemon mode and offline captures don't mix.");

		if (!p0f_context.log_file && !p0f_context.api_sock)
			FATAL("Daemon mode requires -o or -s.");

#ifdef __CYGWIN__

		if (switch_user)
			SAYF("[!] Note: under cygwin, -u is largely useless.\n");

#else

		if (!p0f_context.switch_user)
			SAYF("[!] Consider specifying -u in daemon mode (see README).\n");

#endif /* ^__CYGWIN__ */
	}

	tzset();
	setlocale(LC_TIME, "C");

	close_spare_fds();

	http_init();

	read_config(p0f_context.fp_file ? p0f_context.fp_file : (uint8_t *)FP_FILE);

	prepare_pcap();
	prepare_bpf();

	if (p0f_context.log_file) open_log();
	if (p0f_context.api_sock) open_api();

	if (daemon_mode) {
		p0f_context.null_fd = open("/dev/null", O_RDONLY);
		if (p0f_context.null_fd < 0) PFATAL("Cannot open '/dev/null'.");
	}

	if (p0f_context.switch_user) drop_privs();

	if (daemon_mode) fork_off();

	signal(SIGHUP, daemon_mode ? SIG_IGN : abort_handler);
	signal(SIGINT, abort_handler);
	signal(SIGTERM, abort_handler);

	if (read_file)
		offline_event_loop();
	else
		live_event_loop();

	if (!daemon_mode)
		SAYF("\nAll done. Processed %lu packets.\n", packet_cnt);

#ifdef DEBUG_BUILD
	destroy_all_hosts();
#endif /* DEBUG_BUILD */

	return 0;
}
