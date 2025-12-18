#pragma once

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// UTILS
#define IP_HEADER_SIZE_DEFAULT sizeof(struct iphdr)
#define TOTAL_QUERIES ((opt.hops_max - opt.hops_min + 1) * opt.queries_by_hops)
#define CURR_QUERY (curr_port - opt.start_port)

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
  size_t queries_by_hops;
  size_t sim_queries;

} trac_opt;

typedef struct {
  uint8_t status;
  uint16_t port;
  struct timeval start;
  struct timeval end;
  struct in_addr addr;
  char ipname[INET_ADDRSTRLEN];

} queries_info;

typedef int socket_t;

extern trac_opt opt;
extern in_port_t curr_port;
extern size_t curr_hops;
extern uint8_t reached;
extern socket_t udp_sock;
extern socket_t icmp_sock;
