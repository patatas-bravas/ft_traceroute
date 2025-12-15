#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define IP_HEADER_SIZE_DEFAULT sizeof(struct iphdr)

#define RECV 0
#define NO_RECV 1

#define ERR_FATAL -1
#define ERR_WARNING -2
#define ERR_NONE -3

typedef struct {
  size_t hops_min;
  size_t hops_max;
  size_t pkt_size;
  size_t queries_by_hops;
  size_t sim_queries;

} trac_opt;

typedef int socket_t;

extern trac_opt opt;
extern uint8_t run;
extern socket_t udp_sock;
extern socket_t icmp_sock;
