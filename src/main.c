#include "traceroute.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
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

uint8_t run = 1;
trac_opt opt;

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

// uint16_t checksum(void *addr, size_t size) {
//   unsigned short *ptr = (unsigned short *)addr;
//   uint32_t sum = 0;
//   while (size > 1) {
//     sum += *ptr;
//     ptr++;
//     size -= 2;
//   }
//   if (size == 1)
//     sum += *(unsigned char *)ptr;
//   sum = (sum >> 16) + (sum & 0xFFFF);
//   sum += (sum >> 16);

//   return ~(uint16_t)sum;
// }

int8_t send_pkt(struct sockaddr_in *dest_addr, queries_info *info) {
  uint8_t *pkt;
  static uint8_t queries_curr = 3;
  static in_port_t start_port = 33434;

  pkt = malloc(opt.pkt_size);
  if (pkt == NULL) {
    fprintf(stderr, "[ERROR][malloc]: %s\n", strerror(errno));
    return ERR_FATAL;
  }
  memset(pkt, 0, opt.pkt_size); // LIBFT

  for (size_t i = 0; i <= opt.sim_queries; i++) {
    if (queries_curr == opt.queries_by_hops) {
      if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &opt.hops_min, sizeof(opt.hops_min)) == -1) {
        fprintf(stderr, "[ERROR][setsockopt]: %s\n", strerror(errno));
        free(pkt);
        return ERR_FATAL;
      }
      queries_curr = 0;
      opt.hops_min++;
    }
    queries_curr++;

    info[i].port = htons(start_port++);
    dest_addr->sin_port = info[i].port;
    if (sendto(udp_sock, pkt, opt.pkt_size, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "[ERROR][sendto]: %s\n", strerror(errno));
      free(pkt);
      return ERR_FATAL;
    }
  }
  free(pkt);
  return 0;
}

double get_diff_ms(struct timeval send, struct timeval recv) {
  return (recv.tv_sec - send.tv_sec) * 1000.0 + (recv.tv_usec - send.tv_usec) / 1000.0;
}

int8_t recv_pkt() {
  uint8_t pkt_recv[512] = {0};

  for (size_t i = 0; i < opt.sim_queries; i++) {
    fd_set fd_read;
    FD_ZERO(&fd_read);
    FD_SET(icmp_sock, &fd_read);
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    int nfd = select(icmp_sock + 1, &fd_read, NULL, NULL, &timeout);
    if (nfd == -1) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        return ERR_WARNING;
      else {
        fprintf(stderr, "[ERROR][select]: %s\n", strerror(errno));
        return ERR_FATAL;
      }

      struct sockaddr_in recv_addr = {0};
      socklen_t recv_addr_size = sizeof(struct sockaddr_in);
      ssize_t recv_bytes = recvfrom(icmp_sock, pkt_recv, 512, 0, (struct sockaddr *)&recv_addr, &recv_addr_size);
      if (recv_bytes == -1) {
        fprintf(stderr, "[ERROR][recvfrom]: %s\n", strerror(errno));
        return ERR_FATAL;
      }
    }
    return 0;
  }

  int8_t dns_resolver(const char *hostname, char *ipname, struct sockaddr_in *addr) {
    struct addrinfo *result;
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;

    uint8_t err = getaddrinfo(hostname, NULL, &hints, &result);
    if (err != 0 || result == NULL) {
      fprintf(stderr, "[ERROR][getaddrinfo]: %s\n", gai_strerror(err));
      return ERR_FATAL;
    }

    *addr = *(struct sockaddr_in *)result->ai_addr;
    freeaddrinfo(result);

    char *buffer = inet_ntoa(addr->sin_addr);
    if (buffer == NULL) {
      fprintf(stderr, "[ERROR][inet_ntoa]: %s\n", strerror(errno));
      return ERR_FATAL;
    }

    strcpy(ipname, buffer); // NEED LIBFT
    return 0;
  }

  int8_t ft_traceroute(struct sockaddr_in * addr_dest) {

    queries_info *info = malloc(sizeof(queries_info) * opt.sim_queries);
    if (info == NULL) {
      fprintf(stderr, "[ERROR][malloc]: %s\n", strerror(errno));
      return ERR_FATAL;
    }

    while (run) {
      if (send_pkt(addr_dest, info) == ERR_FATAL)
        return ERR_FATAL;

      if (recv_pkt(info) == ERR_FATAL)
        return ERR_FATAL;
    }

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
    opt.sim_queries = 15;

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
