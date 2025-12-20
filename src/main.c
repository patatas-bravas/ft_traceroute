#include "traceroute.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

socket_t udp_sock;
socket_t icmp_sock;

options_t opts;
in_port_t curr_port;
size_t curr_hops;
uint8_t reached = 0;

socket_t init_socket() {
  udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_sock == -1) {
    fprintf(stderr, "[ERROR][socket]: %s\n", strerror(errno));
    return ERR_FATAL;
  }

  icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (icmp_sock == -1) {
    if (errno == EPERM)
      fprintf(stderr, "[WARNING][ft_traceroute]: requires root privileges\n");
    else
      fprintf(stderr, "[ERROR][socket]: %s\n", strerror(errno));
    return ERR_FATAL;
  }

  return 0;
}

int8_t send_pkt(struct sockaddr_in *dest_addr, probe_t *probes) {
  uint8_t *pkt;
  pkt = malloc(opts.pkt_size);
  if (pkt == NULL) {
    fprintf(stderr, "[ERROR][malloc]: %s\n", strerror(errno));
    return ERR_FATAL;
  }
  memset(pkt, 0, opts.pkt_size); // LIBFT

  for (size_t i = 0; i < opts.sim_probes; i++) {
    if (CURR_PROBES % opts.probes_by_hops == 0) {
      if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &curr_hops, sizeof(curr_hops)) == -1) {
        fprintf(stderr, "[ERROR][setsockopt]: %s\n", strerror(errno));
        free(pkt);
        return ERR_FATAL;
      }
      curr_hops++;
    }
    probes[CURR_PROBES].port = htons(curr_port);
    dest_addr->sin_port = probes[CURR_PROBES].port;
    if (sendto(udp_sock, pkt, opts.pkt_size, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "[ERROR][sendto]: %s\n", strerror(errno));
      free(pkt);
      return ERR_FATAL;
    }
    probes[CURR_PROBES].status = SEND;
    gettimeofday(&probes[CURR_PROBES].start, NULL);
    curr_port++;
  }
  free(pkt);
  return 0;
}

double get_elapsed_time(struct timeval start, struct timeval end) {
  return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
}

int8_t get_udp_data(const uint8_t *buffer, probe_t *probes, struct in_addr recv_addr) {
  struct iphdr *ip = (struct iphdr *)buffer;
  struct icmphdr *icmp = (struct icmphdr *)(buffer + (ip->ihl * sizeof(int32_t)));
  struct iphdr *ipudp = (struct iphdr *)(icmp + 1);
  struct udphdr *udp = (struct udphdr *)((uint8_t *)ipudp + (ipudp->ihl * sizeof(int32_t)));

  in_port_t port = ntohs(udp->dest);
  size_t i = port - opts.start_port;
  gettimeofday(&probes[i].end, NULL);
  probes[i].addr = recv_addr;
  probes[i].port = port;
  probes[i].status = RECEIVED;
  probes[i].type = icmp->type;
  probes[i].elapsed_time = get_elapsed_time(probes[i].start, probes[i].end);
  return 0;
}

int8_t recv_pkt(probe_t *probes) {
  uint8_t buffer[512] = {0};

  for (size_t i = 0; i < opts.sim_probes; i++) {
    fd_set fd_read;
    FD_ZERO(&fd_read);
    FD_SET(icmp_sock, &fd_read);
    int nfd = select(icmp_sock + 1, &fd_read, NULL, NULL, NULL);
    if (nfd == -1) {
      fprintf(stderr, "[ERROR][select]: %s\n", strerror(errno));
      free(probes);
      return ERR_FATAL;
    }
    if (nfd == 0)
      return 0;

    struct sockaddr_in recv_addr = {0};
    socklen_t recv_addr_size = sizeof(struct sockaddr_in);
    ssize_t recv_bytes = recvfrom(icmp_sock, buffer, 512, 0, (struct sockaddr *)&recv_addr, &recv_addr_size);
    if (recv_bytes == -1) {
      fprintf(stderr, "[ERROR][recvfrom]: %s\n", strerror(errno));
      return ERR_FATAL;
    }
    get_udp_data(buffer, probes, recv_addr.sin_addr);
  }
  return 0;
}

int8_t dns_resolver(const char *hostname, char *ipname, struct sockaddr_in *addr) {
  struct addrinfo *result;
  struct addrinfo hints = {0};
  hints.ai_family = AF_INET;

  uint8_t ret = getaddrinfo(hostname, NULL, &hints, &result);
  if (ret != 0 || result == NULL) {
    fprintf(stderr, "[ERROR][getaddrinfo]: %s\n", gai_strerror(ret));
    return ERR_FATAL;
  }

  *addr = *(struct sockaddr_in *)result->ai_addr;
  freeaddrinfo(result);

  strcpy(ipname, inet_ntoa(addr->sin_addr)); // NEED LIBFT
  if (ipname == NULL) {
    fprintf(stderr, "[ERROR][inet_ntoa]: %s\n", strerror(errno));
    return ERR_FATAL;
  }

  return 0;
}

int8_t print_probes(probe_t *probes) {
  static size_t i = 0;
  static double max_elapsed_time = 0;

  while (i < TOTAL_PROBES) {
    if (i % opts.probes_by_hops == 0) {
      printf("%2ld  ", i / opts.probes_by_hops);
    }

    switch (probes[i].status) {
    case NO_SEND:
      return 0;
    case SEND:
      struct timeval curr = {0};
      gettimeofday(&curr, NULL);
      if (get_elapsed_time(probes[i].start, curr) >= max_elapsed_time || probes[i].status == RECEIVED)
        printf("* ");
      break;
    case RECEIVED:
      max_elapsed_time = get_elapsed_time(probes[i].start, probes[i].end) * 3;
      if (probes[i].type == ICMP_TIME_EXCEEDED || probes[i].type == ICMP_ECHOREPLY) {
        if (i % opts.probes_by_hops == 0 || memcmp(&probes[i].addr, &probes[i - 1].addr, sizeof(struct in_addr))) {
          printf("%s ", inet_ntoa(probes[i].addr));
        }
        printf("%0.2lf ms ", probes[i].elapsed_time);
      }
      probes[i].type = RECEIVED;
      break;
    case PRINTED:
      fprintf(stderr, "WTF\n");
      exit(EXIT_FAILURE);
    }

    if (i % opts.probes_by_hops == opts.probes_by_hops - 1) {
      max_elapsed_time *= 10;
      printf("\n");
    }
    i++;
  }
  return 0;
}

int8_t ft_traceroute(struct sockaddr_in *addr_dest) {
  probe_t *probes = malloc(sizeof(probe_t) * TOTAL_PROBES);
  if (probes == NULL) {
    fprintf(stderr, "[ERROR][malloc]: %s\n", strerror(errno));
    return ERR_FATAL;
  }

  while (CURR_PROBES < TOTAL_PROBES && !reached) {
    if (send_pkt(addr_dest, probes) == ERR_FATAL) {
      free(probes);
      return ERR_FATAL;
    }

    if (recv_pkt(probes) == ERR_FATAL) {
      free(probes);
      return ERR_FATAL;
    }

    if (print_probes(probes) == ERR_FATAL) {
      free(probes);
      return ERR_FATAL;
    }
  }

  free(probes);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("ICI on va print le help!\n");
    return 0;
  }

  if (init_socket() == ERR_FATAL)
    return 1;
  char *hostname = argv[argc - 1];
  char ipname[INET_ADDRSTRLEN];
  struct sockaddr_in addr;
  opts.pkt_size = 40;
  opts.hops_min = 1;
  opts.hops_max = 30;
  opts.probes_by_hops = 3;
  opts.sim_probes = 16;
  opts.start_port = 33434;
  curr_port = opts.start_port;
  curr_hops = opts.hops_min;

  if (dns_resolver(hostname, ipname, &addr) == ERR_FATAL) {
    close(udp_sock);
    close(icmp_sock);
    return 2;
  }

  printf("traceroute to %s (%s), %ld hops max, %ld byte packets\n", hostname, ipname, opts.hops_max,
         opts.pkt_size + sizeof(struct iphdr));

  if (ft_traceroute(&addr) == ERR_FATAL) {
    close(udp_sock);
    close(icmp_sock);
    return 3;
  }

  close(udp_sock);
  close(icmp_sock);
  return 0;
}
