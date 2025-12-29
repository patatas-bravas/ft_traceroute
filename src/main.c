#include "traceroute.h"
#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <errno.h>
#include <getopt.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct options opts;

static enum error init_socket(int *fd) {
  fd[UDP] = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd[UDP] == -1) {
    fprintf(stderr, "[ERROR][init_socket][socket]: %s\n", strerror(errno));
    return ERROR;
  }

  fd[ICMP] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (fd[ICMP] == -1) {
    if (errno == EPERM)
      fprintf(stderr, "ft_traceroute: requires root privileges\n");
    else
      fprintf(stderr, "[ERROR][init_socket][socket]: %s\n", strerror(errno));
    return ERROR;
  }

  uint8_t buffer[512];
  while (recvfrom(fd[ICMP], buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL) > 0) {
  }

  return SUCCESS;
}

static enum error send_datagram(struct sockaddr_in *dest_addr, struct probe *probes, struct trace_state *state,
                                int *fd) {
  uint8_t *dgram;
  dgram = calloc(opts.dgram_size, sizeof(uint8_t));
  if (dgram == NULL) {
    fprintf(stderr, "[ERROR][send_datagram][malloc]: %s\n", strerror(errno));
    return ERROR;
  }

  size_t i = state->port_curr - opts.port_start;
  while (state->probes_flight < opts.probes_sim && i < TOTAL_PROBES) {
    if (i % opts.probes_by_hops == 0) {
      if (setsockopt(fd[UDP], IPPROTO_IP, IP_TTL, &state->hops_curr, sizeof(state->hops_curr)) == -1) {
        fprintf(stderr, "[ERROR][send_datagram][setsockopt]: %s\n", strerror(errno));
        free(dgram);
        return ERROR;
      }
      state->hops_curr++;
    }

    gettimeofday(&probes[i].start, NULL);
    probes[i].status = SENT;
    probes[i].port = htons(state->port_curr);
    dest_addr->sin_port = probes[i].port;

    if (sendto(fd[UDP], dgram, opts.dgram_size, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "[ERROR][send_datagram][sendto]: %s\n", strerror(errno));
      free(dgram);
      return ERROR;
    }
    state->port_curr++;
    state->probes_flight++;
    i++;
  }
  free(dgram);
  return SUCCESS;
}

static inline double get_elapsed_time(struct timeval start, struct timeval end) {
  return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
}

static void handle_datagram(const uint8_t *buffer, struct probe *probes, struct in_addr recv_addr,
                            struct trace_state *state) {
  struct iphdr *ip = (struct iphdr *)buffer;
  struct icmphdr *icmp = (struct icmphdr *)(buffer + (ip->ihl * sizeof(int32_t)));
  struct iphdr *ipudp = (struct iphdr *)(icmp + 1);
  struct udphdr *udp = (struct udphdr *)((uint8_t *)ipudp + (ipudp->ihl * sizeof(int32_t)));

  in_port_t port = ntohs(udp->dest);
  size_t i = port - opts.port_start;
  gettimeofday(&probes[i].end, NULL);
  probes[i].addr = recv_addr;
  probes[i].port = port;
  probes[i].status = RECEIVED;
  probes[i].type = icmp->type;
  probes[i].code = icmp->code;
  probes[i].elapsed_time = get_elapsed_time(probes[i].start, probes[i].end);
  state->probes_flight--;
  if (probes[i].type == ICMP_DEST_UNREACH && state->reached == false) {
    state->reached = true;
    state->end = i - (i % opts.probes_by_hops) + (opts.probes_by_hops - 1);
  }
}

static enum error print_probes(struct probe *probes, const struct trace_state *state) {
  static size_t i = 0;

  while (probes[i].status == PRINTABLE) {
    const size_t hop_idx = i % opts.probes_by_hops;
    if (hop_idx == 0) {
      printf("%2ld ", i / opts.probes_by_hops + 1);
    }

    if (probes[i].addr.s_addr == INADDR_ANY) {
      printf(" *");
    } else {
      if (hop_idx == 0 || probes[i].addr.s_addr != probes[i - 1].addr.s_addr) {
        printf(" %s", inet_ntoa(probes[i].addr));
      }
      printf("  %0.3lf ms", probes[i].elapsed_time);
      switch (probes[i].code) {
      case ICMP_HOST_UNREACH:
        printf(" !H");
        break;
      case ICMP_PROT_UNREACH:
        printf(" !P");
        break;
      case ICMP_SR_FAILED:
        printf(" !S");
        break;
      case ICMP_FRAG_NEEDED:
        printf(" !F");
        break;
      case ICMP_PREC_VIOLATION:
        printf(" !V");
        break;
      case ICMP_PREC_CUTOFF:
        printf(" !C");
        break;
      default:
        break;
      }
    }
    fflush(stdout);
    if (hop_idx == opts.probes_by_hops - 1)
      printf("\n");

    if (i == state->end)
      return SUCCESS;
    i++;
  }
  return IGNORE;
}

static enum error recv_datagram(struct probe *probes, struct trace_state *state, int *fd) {
  struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
  uint8_t buffer[512] = {0};
  fd_set fd_read;
  FD_ZERO(&fd_read);
  FD_SET(fd[ICMP], &fd_read);

  if (state->reached == false) {
    int nfd = select(fd[ICMP] + 1, &fd_read, NULL, NULL, &timeout);
    if (nfd == -1) {
      fprintf(stderr, "[ERROR][recv_datagram][select]: %s\n", strerror(errno));
      free(probes);
      return ERROR;
    }
    if (nfd == 0) {
      return SUCCESS;
    }
  }

  struct sockaddr_in recv_addr = {0};
  socklen_t recv_addr_size = sizeof(struct sockaddr_in);
  ssize_t recv_bytes;

  while ((recv_bytes = recvfrom(fd[ICMP], buffer, 512, MSG_DONTWAIT, (struct sockaddr *)&recv_addr, &recv_addr_size)) >
         0)
    handle_datagram(buffer, probes, recv_addr.sin_addr, state);

  if (recv_bytes == -1) {
    if (errno == EWOULDBLOCK || errno == EAGAIN)
      return 0;
    fprintf(stderr, "[ERROR][recv_datagram][recvfrom]: %s\n", strerror(errno));
    return ERROR;
  }

  return SUCCESS;
}

static enum error dns_resolver(const char *hostname, char *ipname, struct sockaddr_in *addr) {
  struct addrinfo *result;
  struct addrinfo hints = {0};
  hints.ai_family = AF_INET;

  uint8_t ret = getaddrinfo(hostname, NULL, &hints, &result);
  if (ret != 0 || result == NULL) {
    fprintf(stderr, "[ERROR][dns_resolver][getaddrinfo]: %s\n", gai_strerror(ret));
    return ERROR;
  }

  *addr = *(struct sockaddr_in *)result->ai_addr;
  freeaddrinfo(result);

  strcpy(ipname, inet_ntoa(addr->sin_addr)); // NEED LIBFT
  if (ipname == NULL) {
    fprintf(stderr, "[ERROR][dns_resolver][inet_ntoa]: %s\n", strerror(errno));
    return ERROR;
  }

  return SUCCESS;
}

static enum error check_probes_timeout(struct probe *probes, struct trace_state *state) {
  static double max_elapsed_time = 0;
  static size_t i = 0;

  while (i < TOTAL_PROBES) {
    switch (probes[i].status) {
    case UNSENT:
      return IGNORE;
    case PRINTABLE:
      break;
    case RECEIVED:
      max_elapsed_time = probes[i].elapsed_time;
      probes[i].status = PRINTABLE;
      break;
    case SENT:
      struct timeval time_now = {0};
      gettimeofday(&time_now, NULL);
      double elapsed_time = get_elapsed_time(probes[i].start, time_now);
      double n = (i / opts.probes_by_hops > 0) ? 5 : 3;
      if (elapsed_time > max_elapsed_time * n) {
        probes[i].status = PRINTABLE;
        state->probes_flight--;
        break;
      }
      return IGNORE;
    }
    i++;
  }

  return SUCCESS;
}

static enum error ft_traceroute(struct sockaddr_in *addr_dest, struct trace_state *state, int *fd) {
  struct probe *probes = calloc(TOTAL_PROBES, sizeof(struct probe)); // LIBFT
  if (probes == NULL) {
    fprintf(stderr, "[ERROR][ft_traceroute][calloc]: %s\n", strerror(errno));
    return ERROR;
  }

  while (true) {
    if (send_datagram(addr_dest, probes, state, fd) == ERROR) {
      free(probes);
      return ERROR;
    }

    if (recv_datagram(probes, state, fd) == ERROR) {
      free(probes);
      return ERROR;
    }

    if (check_probes_timeout(probes, state) == ERROR) {
      free(probes);
      return ERROR;
    }

    if (print_probes(probes, state) == SUCCESS) {
      free(probes);
      return SUCCESS;
    }
  }

  free(probes);
  return ERROR;
}

static inline void print_options() {
  fprintf(stderr, "Usage: ft_traceroute [ -n ] [ -f first_ttl ] [ -m max_ttl ] [ -N squeries ] [ -p port ] [ -q "
                  "nqueries ] host [ packetlen ]\n");
  fprintf(stderr, "  -n                                   Do not resolve IP addresses to their domain names\n");
  fprintf(stderr, "  -f first_ttl  --first=first_ttl      Start from the first_ttl hop (instead from 1)\n");
  fprintf(stderr,
          "  -m max_ttl  --max-hops=max_ttl       Set the max number of hops (max TTL to be reached). Default is 30\n");
  fprintf(stderr, "  -q nqueries  --queries=nqueries      Set the number of probes per each hop. Default is 3\n");
  fprintf(
      stderr,
      "  -N squeries  --sim-queries=squeries  Set the number of probes to be tried simultaneously (default is 16)\n");
  fprintf(stderr, "  -p port  --port=port                 Set the destination port to use. It is either initial udp "
                  "port value for \"default\" method (incremented by each probe, default is 33434)\n");
}

enum error handle_options(int argc, char **argv, char *hostname) {
  opts.dgram_size = DGRAM_SIZE_DEFAULT;
  opts.hops_min = HOPS_MIN_DEFAULT;
  opts.hops_max = HOPS_MAX_DEFAULT;
  opts.probes_by_hops = PROBES_BY_HOPS_DEFAULT;
  opts.probes_sim = PROBES_SIM_DEFAULT;
  opts.port_start = PORT_START_DEFAULT;
  opts.dns_lookup = true;

  int opt_idx;
  int opt_curr;
  char *endptr;

  struct option opt[] = {{"dns_lookup", no_argument, 0, 'n'},     {"help", no_argument, 0, 'h'},
                         {"first", required_argument, 0, 'f'},    {"max-hops", required_argument, 0, 'm'},
                         {"nqueries", required_argument, 0, 'q'}, {"squeries", required_argument, 0, 'N'},
                         {"port", required_argument, 0, 'p'},     {0, 0, 0, 0}};

  while ((opt_curr = getopt_long(argc, argv, "nhf:q:p:m:N:", opt, &opt_idx)) != -1) {
    switch (opt_curr) {
    case 'n':
      opts.dns_lookup = false;
      break;
    case 'h':
      print_options();
      return ERROR;
    case 'f':
      opts.hops_min = strtol(optarg, &endptr, 10);
      if (errno == ERANGE || *endptr || opts.hops_min <= 0 || opts.hops_min >= 255) {
        fprintf(stderr, "first hop out of range\n");
        return ERROR;
      }
      break;
    case 'm':
      opts.hops_max = strtol(optarg, &endptr, 10);
      if (errno == ERANGE || *endptr || opts.hops_max <= 0 || opts.hops_max > 255) {
        fprintf(stderr, "max hops cannot be more than 255\n");
        return ERROR;
      }
      break;
    case 'q':
      opts.probes_by_hops = strtol(optarg, &endptr, 10);
      if (errno == ERANGE || *endptr || opts.probes_by_hops <= 0 || opts.probes_by_hops >= 10) {
        fprintf(stderr, "no more than 10 probes per hop\n");
        return ERROR;
      }
      break;
    case 'N':
      opts.probes_sim = strtol(optarg, &endptr, 10);
      if (errno == ERANGE || *endptr || opts.probes_sim <= 0 || opts.probes_sim > 32) {
        fprintf(stderr, "no more than 32 probes simultaneously\n");
        return ERROR;
      }
      break;
    case 'p':
      opts.port_start = strtol(optarg, &endptr, 10);
      if (errno == ERANGE || *endptr || opts.port_start <= 0 || opts.port_start > 65535) {
        fprintf(stderr, "port range is between 1-65535\n");
        return ERROR;
      }
      break;
    }
  }

  if (opts.hops_min > opts.hops_max) {
    fprintf(stderr, "first hop out of range");
    return ERROR;
  }

  switch (argc - optind) {
  case 2:
    opts.dgram_size = strtol(argv[optind + 1], &endptr, 10);
    if (errno == ERANGE || *endptr || opts.dgram_size > 65000) {
      fprintf(stderr, "too big packetlen %ld specified\n", opts.dgram_size);
      return ERROR;
    }
    if (opts.dgram_size < 28) {
      fprintf(stderr, "too small packetlen %ld specified\n", opts.dgram_size);
      return ERROR;
    }
  case 1:
    hostname = argv[optind];
    break;
  case 0:
    fprintf(stderr, "Specify \"host\" missing argument.\n");
    return ERROR;
  default:
    fprintf(stderr, "Extra arg '%s'\n", argv[optind + 2]);
    return ERROR;
  }

  return SUCCESS;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    print_options();
    return 0;
  }

  int fd[2];
  if (init_socket(fd) == ERROR)
    return 1;

  char *hostname = argv[argc - 1];
  char ipname[INET_ADDRSTRLEN];
  struct sockaddr_in addr;
  if (dns_resolver(hostname, ipname, &addr) == ERROR) {
    close(fd[UDP]);
    close(fd[ICMP]);
    return 2;
  }

  printf("traceroute to %s (%s), %ld hops max, %ld byte packets\n", hostname, ipname, opts.hops_max, opts.dgram_size);

  struct trace_state state = {0};
  state.port_curr = opts.port_start;
  state.hops_curr = opts.hops_min;
  state.end = SIZE_MAX;

  if (ft_traceroute(&addr, &state, fd) == ERROR) {
    close(fd[UDP]);
    close(fd[ICMP]);
    return 3;
  }

  close(fd[UDP]);
  close(fd[ICMP]);
  return 0;
}
