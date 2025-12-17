#include "traceroute.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
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
#include <unistd.h>

socket_t udp_sock;
socket_t icmp_sock;

trac_opt opt;
in_port_t curr_port;
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

int8_t send_pkt(struct sockaddr_in *dest_addr, queries_info *queries) {
  uint8_t *pkt;
  pkt = malloc(opt.pkt_size);
  if (pkt == NULL) {
    fprintf(stderr, "[ERROR][malloc]: %s\n", strerror(errno));
    return ERR_FATAL;
  }
  memset(pkt, 0, opt.pkt_size); // LIBFT

  for (size_t i = 0; i < opt.sim_queries; i++) {
    if ((curr_port - opt.start_port) % opt.queries_by_hops == 0) {
      if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &opt.hops_min, sizeof(opt.hops_min)) == -1) {
        fprintf(stderr, "[ERROR][setsockopt]: %s\n", strerror(errno));
        free(pkt);
        return ERR_FATAL;
      }
      opt.hops_min++;
    }
    queries[i].port = htons(curr_port++);
    dest_addr->sin_port = queries[i].port;
    if (sendto(udp_sock, pkt, opt.pkt_size, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "[ERROR][sendto]: %s\n", strerror(errno));
      free(pkt);
      return ERR_FATAL;
    }
    queries[i].status = SEND;
    gettimeofday(&queries[i].start, NULL);
  }
  free(pkt);
  return 0;
}

double get_elapsed_time(struct timeval send, struct timeval recv) {
  return (recv.tv_sec - send.tv_sec) * 1000.0 + (recv.tv_usec - send.tv_usec) / 1000.0;
}

int8_t get_udp_data(const uint8_t *buffer, queries_info *queries, struct in_addr recv_addr) {
  struct iphdr *ip = (struct iphdr *)buffer;
  struct icmphdr *icmp = (struct icmphdr *)(buffer + (ip->ihl * sizeof(int32_t)));
  struct iphdr *ipudp = (struct iphdr *)(icmp + 1);
  struct udphdr *udp = (struct udphdr *)((uint8_t *)ipudp + (ipudp->ihl * sizeof(int32_t)));

  in_port_t port = ntohs(udp->dest);
  printf("port = %d\n", port);
  size_t i = port - opt.start_port;
  printf("index = %ld\n", i);
  queries[i].addr = recv_addr;
  queries[i].port = port;
  queries[i].status = RECV;
  gettimeofday(&queries[i].end, NULL);
  if (icmp->type == ICMP_ECHOREPLY && i % (opt.queries_by_hops - 1) == 0) {
    reached = 1;
  }
  return 0;
}

int8_t recv_pkt(queries_info *queries) {
  uint8_t buffer[512] = {0};

  fd_set fd_read;
  FD_ZERO(&fd_read);
  FD_SET(icmp_sock, &fd_read);
  struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
  int nfd = select(icmp_sock + 1, &fd_read, NULL, NULL, &timeout);
  if (nfd == -1) {
    fprintf(stderr, "[ERROR][select]: %s\n", strerror(errno));
    free(queries);
    return ERR_FATAL;
  }
  if (nfd == 0)
    return 0;

  for (size_t i = 0; i < opt.sim_queries; i++) {
    struct sockaddr_in recv_addr = {0};
    socklen_t recv_addr_size = sizeof(struct sockaddr_in);
    ssize_t recv_bytes = recvfrom(icmp_sock, buffer, 512, 0, (struct sockaddr *)&recv_addr, &recv_addr_size);
    if (recv_bytes == -1) {
      fprintf(stderr, "[ERROR][recvfrom]: %s\n", strerror(errno));
      return ERR_FATAL;
    }
    get_udp_data(buffer, queries, recv_addr.sin_addr);
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

int8_t print_queries(queries_info *queries) {
  for (static size_t i = 0; i < TOTAL_QUERIES; i++) {
    // if (i % opt.queries_by_hops == 0)
    // printf("%2ld ", i / opt.queries_by_hops);
    if (queries[i].status != SEND)
      return 0;
  }
  return 0;
}

int8_t ft_traceroute(struct sockaddr_in *addr_dest) {

  queries_info *queries = malloc(sizeof(queries_info) * TOTAL_QUERIES);
  if (queries == NULL) {
    fprintf(stderr, "[ERROR][malloc]: %s\n", strerror(errno));
    return ERR_FATAL;
  }
  memset(queries, 0, sizeof(queries_info) * TOTAL_QUERIES); // LIBFT

  while (CURR_QUERIE < TOTAL_QUERIES && !reached) {
    if (send_pkt(addr_dest, queries) == ERR_FATAL) {
      free(queries);
      return ERR_FATAL;
    }

    if (recv_pkt(queries) == ERR_FATAL) {
      free(queries);
      return ERR_FATAL;
    }

    if (print_queries(queries) == ERR_FATAL) {
      free(queries);
      return ERR_FATAL;
    }
  }
  free(queries);
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
  opt.pkt_size = 40;
  opt.hops_min = 1;
  opt.hops_max = 30;
  opt.queries_by_hops = 3;
  opt.sim_queries = 16;
  opt.start_port = 33434;
  curr_port = opt.start_port;

  if (dns_resolver(hostname, ipname, &addr) == ERR_FATAL) {
    close(udp_sock);
    close(icmp_sock);
    return 2;
  }
  printf("traceroute to %s (%s), %ld hops max, %ld byte packets\n", hostname, ipname, opt.hops_max,
         opt.pkt_size + IP_HEADER_SIZE_DEFAULT);
  if (ft_traceroute(&addr) == ERR_FATAL) {
    close(udp_sock);
    close(icmp_sock);
    return 3;
  }

  close(udp_sock);
  close(icmp_sock);
  return 0;
}
