#pragma once

#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>

#define TOTAL_PROBES ((opts.hops_max - opts.hops_min + 1) * opts.probes_by_hops)
#define HEADERS_SIZE (sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) * 2)

#define DGRAM_SIZE_DEFAULT 60
#define HOPS_MIN_DEFAULT 1
#define HOPS_MAX_DEFAULT 30
#define PROBES_BY_HOPS_DEFAULT 3
#define PORT_START_DEFAULT 33434

#define OPT_MAX_PKT_SIZE 65000
#define OPT_MIN_PKT_SIZE 28
#define OPT_MAX_PROBES_HOP 10

typedef enum {
	UDP,
	ICMP,
} Socket;

typedef enum {
	SUCCESS = 0,
	IGNORE = -1,
	WARNING = -2,
	ERROR = -3,
} ErrorType;

typedef struct {
	size_t port_start;
	size_t hops_min;
	size_t hops_max;
	size_t dgram_size;
	size_t probes_by_hops;
	bool dns_lookup;
} Options;

typedef struct {
	struct timeval start;
	struct in_addr addr;
	uint8_t type;
	uint8_t code;
	double elapsed_time;
} Probe;

typedef struct {
	in_port_t port_curr;
	uint8_t hops_curr;
	size_t end;
} State;

extern Options opts;
