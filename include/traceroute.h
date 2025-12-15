#pragma once

#include <stdint.h>

#define UNINISIALIZE -42
#define PACKET_DEFAULT_SIZE 60
#define IP_HEADER_SIZE_DEFAULT 20

// recv
#define RECV 0
#define NO_RECV 1

#define ERR_FATAL -1
#define ERR_WARNING -2
#define ERR_NONE -3

typedef struct {
  uint32_t hops;
  uint32_t pkt_size;
} trac_opt;
typedef int socket_t;

extern trac_opt opt;
