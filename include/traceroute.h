#pragma once

#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#define TOTAL_PROBES ((opts.hops_max - opts.hops_min + 1) * opts.probes_by_hops)

#define DGRAM_SIZE_DEFAULT 40
#define HOPS_MIN_DEFAULT 1
#define HOPS_MAX_DEFAULT 30
#define PROBES_BY_HOPS_DEFAULT 3
#define PROBES_SIM_DEFAULT 16
#define PORT_START_DEFAULT 33434

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
	int64_t port_start;
	int64_t hops_min;
	int64_t hops_max;
	int64_t dgram_size;
	int64_t probes_by_hops;
	int64_t probes_sim;
	bool dns_lookup;
};

struct probe {
	enum status status;
	uint16_t port;
	struct timeval start;
	struct timeval end;
	struct in_addr addr;
	uint8_t type;
	uint8_t code;
	int64_t elapsed_time;
};

struct trace_state {
	in_port_t port_curr;
	in_port_t port_reach;
	uint8_t hops_curr;
	size_t probes_flight;
	bool reached;
	size_t end;
};

extern struct options opts;
