#include "traceroute.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

socket_t init_socket() {
  socket_t fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (fd == -1) {
    perror("[ERROR][socket]");
    return ERR_FATAL;
  }
  return 0;
}

int8_t dns_resolver(const char *hostname, char *ipname, struct sockaddr_in *addr) {
  struct addrinfo *result;
  if (getaddrinfo(hostname, NULL, NULL, &result) == -1) {
    perror("[ERROR][getaddrinfo]");
    return ERR_FATAL;
  }

  addr = (struct sockaddr_in *)result->ai_addr;
  freeaddrinfo(result);

  char *buffer = inet_ntoa(addr->sin_addr);
  if (buffer == NULL) {
    perror("[ERROR][inet_ntoa]");
    return ERR_FATAL;
  }
  strcpy(ipname, buffer); // NEED LIBFT
  return 0;
}

int8_t ft_traceroute(const socket_t fd, const char *hostname, const char *ipname, const struct sockaddr_in addr) {

  while (1) {
  }
}

int main(int argc, char **argv) {
  socket_t fd = init_socket();
  if (fd == ERR_FATAL)
    return 1;

  char *hostname = argv[argc - 1];
  char ipname[INET_ADDRSTRLEN];
  struct sockaddr_in addr;

  if (dns_resolver(hostname, ipname, &addr) == ERR_FATAL) {
    close(fd);
    return 2;
  }

  if (ft_traceroute() == ERR_FATAL) {
    close(fd);
    return 3;
  }
  close(fd);
}
