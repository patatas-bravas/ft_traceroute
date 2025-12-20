#pragma once

#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

// UTILS
#define TOTAL_PROBES ((opts.hops_max - opts.hops_min + 1) * opts.probes_by_hops)
#define CURR_PROBES (curr_port - opts.start_port)

// ERROR
#define ERR_FATAL -1
#define ERR_WARNING -2
#define ERR_NONE -3

// STATUS
#define NO_SEND 0
#define SEND 1
#define RECEIVED 2
#define PRINTED 3

typedef struct {
  size_t start_port;
  size_t hops_min;
  size_t hops_max;
  size_t pkt_size;
  size_t probes_by_hops;
  size_t sim_probes;

} options_t;

typedef struct {
  uint8_t status;
  uint16_t port;
  struct timeval start;
  struct timeval end;
  struct in_addr addr;
  char ipname[INET_ADDRSTRLEN];
  uint8_t type;
  double elapsed_time;

} probe_t;

typedef int socket_t;

extern options_t opt;
extern in_port_t curr_port;
extern size_t curr_hops;
extern uint8_t reached;
extern socket_t udp_sock;
extern socket_t icmp_sock;
