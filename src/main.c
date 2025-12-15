#include "traceroute.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

uint8_t run = 1;
trac_opt opt;

socket_t init_socket() {
  socket_t fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (fd == -1) {
    if (errno == EPERM)
      fprintf(stderr, "[WARNING][ft_traceroute]: requires root privileges\n");
    else
      fprintf(stderr, "[ERROR][socket]: %s\n", strerror(errno));
    return ERR_FATAL;
  }
  return fd;
}

uint16_t checksum(void *addr, size_t size) {
  unsigned short *ptr = (unsigned short *)addr;
  uint32_t sum = 0;
  while (size > 1) {
    sum += *ptr;
    ptr++;
    size -= 2;
  }
  if (size == 1)
    sum += *(unsigned char *)ptr;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  return ~(uint16_t)sum;
}

int8_t send_pkt(socket_t fd, const struct sockaddr_in *dest_addr, struct timeval *pkt_time_start) {
  static uint8_t sequence;
  static uint8_t ttl = 1;
  uint8_t *pkt;

  pkt = malloc(opt.pkt_size);
  if (pkt == NULL) {
    fprintf(stderr, "[ERROR][malloc]: %s\n", strerror(errno));
    return ERR_FATAL;
  }
  memset(pkt, 0, opt.pkt_size); // LIBFT

  if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(uint8_t)) == -1) {
    fprintf(stderr, "[ERROR][setsockopt]: %s\n", strerror(errno));
    free(pkt);
    return ERR_FATAL;
  }
  if (ttl == 255) {
    fprintf(stderr, "[ERROR][ttl]: WTF ttl at 255\n");
    free(pkt);
    return ERR_FATAL;
  }
  ttl += 1;

  for (size_t i = 0; i < 3; i++) {
    struct icmphdr *icmp = (struct icmphdr *)pkt;
    icmp->type = ICMP_ECHO;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = sequence++;
    char *payload = (char *)pkt + sizeof(struct icmphdr);
    memset(payload, 'M', opt.pkt_size - sizeof(struct icmphdr)); // LIBFT
    icmp->checksum = checksum(pkt, opt.pkt_size);

    gettimeofday(&pkt_time_start[i], NULL);

    if (sendto(fd, pkt, opt.pkt_size, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) == -1) {
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

int8_t handle_recv_pkt(uint8_t *pkt_recv, struct sockaddr_in recv_addr, struct timeval *pkt_time_start,
                       struct timeval pkt_time_end, char *last_ipname) {
  struct iphdr *ip = (struct iphdr *)pkt_recv;
  struct icmphdr *icmp = (struct icmphdr *)(pkt_recv + ip->ihl * 4);

  char *ipname = inet_ntoa(recv_addr.sin_addr);
  if (ipname == NULL) {
    fprintf(stderr, "[ERROR][inet_ntoa]: %s\n", strerror(errno));
    return ERR_FATAL;
  }

  if (*last_ipname == '\0' || strcmp(last_ipname, ipname)) { // LIBFT
    printf("%s  ", ipname);
    strcpy(last_ipname, ipname);
  }

  printf("%0.3lf ms  ", get_diff_ms(pkt_time_start[icmp->un.echo.sequence % 3], pkt_time_end));
  if (icmp->type == ICMP_ECHOREPLY)
    run = 0;
  return 0;
}

int8_t recv_pkt(socklen_t fd, struct timeval *pkt_time_start) {
  char last_ipname[INET_ADDRSTRLEN] = {0};
  uint8_t pkt_recv[512] = {0};

  static uint8_t nhops = 1;
  printf("%2d  ", nhops);
  nhops++;

  for (size_t i = 0; i < 3; i++) {
    fd_set fd_read;
    FD_ZERO(&fd_read);
    FD_SET(fd, &fd_read);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 500000};
    int nfd = select(fd + 1, &fd_read, NULL, NULL, &timeout);
    if (nfd == -1) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        return ERR_WARNING;
      else {
        fprintf(stderr, "[ERROR][select]: %s\n", strerror(errno));
        return ERR_FATAL;
      }
    } else if (nfd == 0)
      printf("* ");
    else {
      struct timeval pkt_time_end = {0};
      gettimeofday(&pkt_time_end, NULL);

      struct sockaddr_in recv_addr = {0};
      socklen_t recv_addr_size = sizeof(struct sockaddr_in);
      ssize_t recv_bytes = recvfrom(fd, pkt_recv, 512, 0, (struct sockaddr *)&recv_addr, &recv_addr_size);
      if (recv_bytes == -1) {
        fprintf(stderr, "[ERROR][recvfrom]: %s\n", strerror(errno));
        return ERR_FATAL;
      }
      handle_recv_pkt(pkt_recv, recv_addr, pkt_time_start, pkt_time_end, last_ipname);
    }
  }
  printf("\n");
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

int8_t ft_traceroute(const socket_t fd, const struct sockaddr_in *addr_dest) {

  struct timeval pkt_time_start[3];
  while (run) {
    if (send_pkt(fd, addr_dest, pkt_time_start) == ERR_FATAL)
      return ERR_FATAL;

    if (recv_pkt(fd, pkt_time_start) == ERR_FATAL)
      return ERR_FATAL;
  }

  return 0;
}

int main(int argc, char **argv) {
  socket_t fd = init_socket();
  if (fd == ERR_FATAL)
    return 1;

  char *hostname = argv[argc - 1];
  char ipname[INET_ADDRSTRLEN];
  struct sockaddr_in addr;
  opt.pkt_size = 60;
  opt.hops = 30;

  if (dns_resolver(hostname, ipname, &addr) == ERR_FATAL) {
    close(fd);
    return 2;
  }

  printf("traceroute to %s (%s), %d hops max, %d byte packets\n", hostname, ipname, opt.hops, opt.pkt_size);
  if (ft_traceroute(fd, &addr) == ERR_FATAL) {
    close(fd);
    return 3;
  }

  close(fd);
  return 0;
}
