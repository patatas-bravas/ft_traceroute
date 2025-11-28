#include "traceroute.h"
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

socket_t init_socket() {
  socket_t fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (fd == -1) {
    perror("[ERROR][socket]");
    return ERR_FATAL;
  }
  return 0;
}

int main() {
  socket_t fd = init_socket();
  if (fd == ERR_FATAL)
    return 1;
  close(fd);
}
