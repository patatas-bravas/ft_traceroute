#include "traceroute.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
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

Options opts;

static ErrorType init_socket(int *fd)
{
	fd[UDP] = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd[UDP] == -1) {
		fprintf(stderr, "[ERROR][init_socket][socket]: %s\n", strerror(errno));
		return ERROR;
	}

	fd[ICMP] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd[ICMP] == -1) {
		close(fd[UDP]);
		if (errno == EPERM)
			fprintf(stderr, "ft_traceroute: requires root privileges\n");
		else
			fprintf(stderr, "[ERROR][init_socket][socket]: %s\n", strerror(errno));
		return ERROR;
	}

	uint8_t buffer[1024];
	while (recvfrom(fd[ICMP], buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL) > 0) {
	}

	return SUCCESS;
}

static ErrorType send_datagram(struct sockaddr_in *dest_addr, Probe *probes, State *state, int *fd, uint8_t *buffer)
{
	size_t i = state->port_curr - opts.port_start;
	if (i % opts.probes_by_hops == 0) {
		if (setsockopt(fd[UDP], IPPROTO_IP, IP_TTL, &state->hops_curr, sizeof(state->hops_curr)) == -1) {
			fprintf(stderr, "[ERROR][send_datagram][setsockopt]: %s\n", strerror(errno));
			return ERROR;
		}
		state->hops_curr++;
	}

	gettimeofday(&probes[i].start, NULL);
	dest_addr->sin_port = htons(state->port_curr);

	if (sendto(fd[UDP], buffer, opts.dgram_size, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) == -1) {
		fprintf(stderr, "[ERROR][send_datagram][sendto]: %s\n", strerror(errno));
		return ERROR;
	}

	state->port_curr++;

	return SUCCESS;
}

static inline double get_elapsed_time_ms(struct timeval start, struct timeval end)
{
	return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
}

static void handle_datagram(const uint8_t *buffer, Probe *probes, struct in_addr recv_addr, State *state)
{
	struct iphdr *ip = (struct iphdr *)buffer;
	struct icmphdr *icmp = (struct icmphdr *)(buffer + (ip->ihl * sizeof(int32_t)));
	struct iphdr *ipudp = (struct iphdr *)(icmp + 1);
	struct udphdr *udp = (struct udphdr *)((uint8_t *)ipudp + (ipudp->ihl * sizeof(int32_t)));

	in_port_t port = ntohs(udp->dest);
	size_t i = port - opts.port_start;
	probes[i].addr = recv_addr;
	probes[i].type = icmp->type;
	probes[i].code = icmp->code;

	struct timeval now = { 0 };
	gettimeofday(&now, NULL);
	probes[i].elapsed_time = get_elapsed_time_ms(probes[i].start, now);

	if (probes[i].type == ICMP_DEST_UNREACH) {
		size_t tmp = i - (i % opts.probes_by_hops) + (opts.probes_by_hops - 1);
		if (tmp < state->end) {
			state->end = tmp;
		}
	}
}

static ErrorType print_probes(Probe *probes, State *state)
{
	size_t i = state->port_curr - opts.port_start - 1;
	const size_t hop_idx = i % opts.probes_by_hops;
	if (hop_idx == 0)
		printf("%2ld ", opts.hops_min++);
	if (probes[i].addr.s_addr == INADDR_ANY) {
		printf(" *");
		fflush(stdout);
	} else {
		if (hop_idx == 0 || probes[i].addr.s_addr != probes[i - 1].addr.s_addr) {
			if (opts.dns_lookup) {
				char *ipname = inet_ntoa(probes[i].addr);
				struct hostent *host = gethostbyaddr(&probes[i].addr, sizeof(probes[i].addr), AF_INET);
				if (host)
					printf(" %s (%s)", host->h_name, ipname);
				else
					printf(" %s (%s)", ipname, ipname);
			} else
				printf(" %s", inet_ntoa(probes[i].addr));
		}
		printf("  %0.3lf ms", probes[i].elapsed_time);
		switch (probes[i].code) {
		case ICMP_HOST_UNREACH:
			printf(" !H");
			break;
		// case ICMP_DEST_UNREACH:
		// 	printf(" !D");
		// 	break;
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

	if (hop_idx == opts.probes_by_hops - 1)
		printf("\n");

	if (i == state->end)
		return SUCCESS;
	return IGNORE;
}

static ErrorType recv_datagram(Probe *probes, State *state, int *fd, uint8_t *buffer)
{
	fd_set fd_read;
	FD_ZERO(&fd_read);
	FD_SET(fd[ICMP], &fd_read);
	struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
	int nfd = select(fd[ICMP] + 1, &fd_read, NULL, NULL, &timeout);
	if (nfd == -1) {
		fprintf(stderr, "[ERROR][recv_datagram][select]: %s\n", strerror(errno));
		return ERROR;
	}

	if (nfd == 0)
		return SUCCESS;

	struct sockaddr_in recv_addr = { 0 };
	socklen_t recv_addr_size = sizeof(struct sockaddr_in);
	ssize_t recv_bytes = recvfrom(fd[ICMP], buffer, opts.dgram_size + HEADERS_SIZE, 0, (struct sockaddr *)&recv_addr, &recv_addr_size);
	if (recv_bytes == -1) {
		fprintf(stderr, "[ERROR][recv_datagram][recvfrom]: %s\n", strerror(errno));
		return ERROR;
	}

	handle_datagram(buffer, probes, recv_addr.sin_addr, state);

	return SUCCESS;
}

static inline ErrorType dns_resolver(const char *hostname, struct sockaddr_in *addr)
{
	struct addrinfo *result;
	struct addrinfo hints = { 0 };
	hints.ai_family = AF_INET;

	uint8_t ret = getaddrinfo(hostname, NULL, &hints, &result);
	if (ret != 0 || result == NULL) {
		fprintf(stderr, "[ERROR][dns_resolver][getaddrinfo]: %s\n", gai_strerror(ret));
		return ERROR;
	}

	*addr = *(struct sockaddr_in *)result->ai_addr;
	freeaddrinfo(result);

	printf("traceroute to %s (%s), %ld hops max, %ld byte packets\n", hostname, inet_ntoa(addr->sin_addr), opts.hops_max, opts.dgram_size);
	return SUCCESS;
}

static ErrorType ft_traceroute(struct sockaddr_in *addr_dest, State *state, int *fd)
{
	Probe *probes = calloc(TOTAL_PROBES, sizeof(Probe));
	uint8_t *buffer = calloc(opts.dgram_size + HEADERS_SIZE, sizeof(uint8_t));

	if (!probes || !buffer) {
		free(probes);
		free(buffer);
		fprintf(stderr, "[ERROR][ft_traceroute][calloc]: %s\n", strerror(errno));
		return ERROR;
	}

	while (true) {
		if (send_datagram(addr_dest, probes, state, fd, buffer) == ERROR)
			break;

		if (recv_datagram(probes, state, fd, buffer) == ERROR)
			break;

		if (print_probes(probes, state) == SUCCESS) {
			break;
		}
	}

	free(probes);
	free(buffer);

	return SUCCESS;
}

static inline void print_options()
{
	fprintf(stderr, "Usage: ft_traceroute [ -n ] [ -f first_ttl ] [ -m max_ttl ] [ -p port ] [ -q nqueries ] host [ packetlen ]\n");
	fprintf(stderr, "  -n                                   Do not resolve IP addresses to their domain names\n");
	fprintf(stderr, "  -f first_ttl  --first=first_ttl      Start from the first_ttl hop (instead from 1)\n");
	fprintf(stderr, "  -m max_ttl  --max-hops=max_ttl       Set the max number of hops (max TTL to be reached). Default is 30\n");
	fprintf(stderr, "  -q nqueries  --queries=nqueries      Set the number of probes per each hop. Default is 3\n");
	fprintf(stderr,
		"  -p port  --port=port                 Set the destination port to use. It is either initial udp port value for \"default\" method (incremented by each probe, default is 33434)\n");
}

static ErrorType handle_options(int argc, char **argv, char **hostname)
{
	opts.dgram_size = DGRAM_SIZE_DEFAULT;
	opts.hops_min = HOPS_MIN_DEFAULT;
	opts.hops_max = HOPS_MAX_DEFAULT;
	opts.probes_by_hops = PROBES_BY_HOPS_DEFAULT;
	opts.port_start = PORT_START_DEFAULT;
	opts.dns_lookup = true;

	int opt_idx;
	int opt_curr;
	char *endptr;

	struct option opt[] = { { "dns_lookup", no_argument, 0, 'n' },	   { "help", no_argument, 0, 'h' },
				{ "first", required_argument, 0, 'f' },	   { "max-hops", required_argument, 0, 'm' },
				{ "nqueries", required_argument, 0, 'q' }, { "squeries", required_argument, 0, 'N' },
				{ "port", required_argument, 0, 'p' },	   { 0, 0, 0, 0 } };

	long tmp;
	while ((opt_curr = getopt_long(argc, argv, "nhf:q:p:m:N:", opt, &opt_idx)) != -1) {
		switch (opt_curr) {
		case 'n':
			opts.dns_lookup = false;
			break;
		case 'h':
			print_options();
			return ERROR;
		case 'f':
			tmp = strtol(optarg, &endptr, 10);
			if (errno == ERANGE || *endptr || tmp <= 0 || tmp >= UINT8_MAX) {
				fprintf(stderr, "first hop out of range\n");
				return ERROR;
			}
			opts.hops_min = tmp;
			break;
		case 'm':
			tmp = strtol(optarg, &endptr, 10);
			if (errno == ERANGE || *endptr || tmp <= 0 || tmp > UINT8_MAX) {
				fprintf(stderr, "max hops cannot be more than 255\n");
				return ERROR;
			}
			opts.hops_max = tmp;
			break;
		case 'q':
			tmp = strtol(optarg, &endptr, 10);
			if (errno == ERANGE || *endptr || tmp <= 0 || tmp > OPT_MAX_PROBES_HOP) {
				fprintf(stderr, "no more than 10 probes per hop\n");
				return ERROR;
			}
			opts.probes_by_hops = tmp;
			break;
		case 'p':
			tmp = strtol(optarg, &endptr, 10);
			if (errno == ERANGE || *endptr || tmp <= 0 || tmp >= UINT16_MAX) {
				fprintf(stderr, "port range is between 1-65535\n");
				return ERROR;
			}
			opts.port_start = tmp;
			break;
		default:
			fprintf(stderr, "Unknow arg\n");
			return ERROR;
			break;
		}
	}

	if (opts.hops_min > opts.hops_max) {
		fprintf(stderr, "first hop out of range");
		return ERROR;
	}

	const uint32_t remaining_arg = argc - optind;
	switch (remaining_arg) {
	case 2:
		tmp = strtol(argv[optind + 1], &endptr, 10);
		if (errno == ERANGE || *endptr || tmp > OPT_MAX_PKT_SIZE) {
			fprintf(stderr, "too big packetlen %ld specified\n", tmp);
			return ERROR;
		}
		if (tmp < OPT_MIN_PKT_SIZE) {
			fprintf(stderr, "too small packetlen %ld specified\n", tmp);
			return ERROR;
		}
		opts.dgram_size = tmp;
		*hostname = argv[optind];
		break;
	case 1:
		*hostname = argv[optind];
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

int main(int argc, char **argv)
{
	if (argc < 2) {
		print_options();
		return 0;
	}

	char *hostname = NULL;
	if (handle_options(argc, argv, &hostname) == ERROR)
		exit(EXIT_FAILURE);

	int fd[2];
	if (init_socket(fd) == ERROR)
		exit(EXIT_FAILURE);

	struct sockaddr_in addr;
	if (dns_resolver(hostname, &addr) == ERROR) {
		close(fd[UDP]);
		close(fd[ICMP]);
		exit(EXIT_FAILURE);
	}

	State state = { .port_curr = opts.port_start, .hops_curr = opts.hops_min, .end = opts.hops_max * opts.probes_by_hops - 1 };
	if (ft_traceroute(&addr, &state, fd) == ERROR) {
		close(fd[UDP]);
		close(fd[ICMP]);
		exit(EXIT_FAILURE);
	}

	close(fd[UDP]);
	close(fd[ICMP]);
	return 0;
}
