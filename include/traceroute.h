#pragma once

#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#define TOTAL_PROBES ((opts.hops_max - opts.hops_min + 1) * opts.probes_by_hops)

enum status {
	UNSENT,
	SENT,
	RECEIVED,
	PRINTABLE,
};

enum socket {
	UDP,
	ICMP,
};

enum error {
	SUCCESS = 0,
	IGNORE = -1,
	WARNING = -2,
	ERROR = -3,
};

struct options {
	size_t port_start;
	size_t hops_min;
	size_t hops_max;
	size_t dgram_size;
	size_t probes_by_hops;
	size_t probes_sim;
};

struct probe {
	enum status status;
	uint16_t port;
	struct timeval start;
	struct timeval end;
	struct in_addr addr;
	uint8_t type;
	uint8_t code;
	double elapsed_time;
};

struct trace_state {
	in_port_t port_curr;
	in_port_t port_reach;
	uint8_t hops_curr;
	size_t probes_flight;
	bool reached;
	size_t end;
};

typedef int socket_t;

extern struct options opts;
