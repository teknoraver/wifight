#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <time.h>

#define MTU 1500

struct __attribute__ ((__packed__)) radiotap {
	uint8_t revision;
	uint8_t pad;
	uint16_t length;
	uint32_t present;
};

struct __attribute__ ((__packed__)) wifi {
	uint16_t type;
	uint16_t duration;
	uint8_t raddr[6];
	uint8_t saddr[6];
	uint8_t bssid[6];
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

struct __attribute__ ((__packed__)) beacon {
	struct radiotap radiotap;
	struct wifi wifi;
	struct mgmt mgmt;
	struct tlv essid;
};

char ** load_words(char *path, int *lines)
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
	words = malloc(*lines * sizeof(char *));
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

int main(int argc, char *argv[])
{
	char c;
	pcap_t *pcap;
	int lines;
	char **words;

	while((c = getopt(argc, argv, "f:")) != -1) {
		switch(c) {
		case 'f':
			words = load_words(optarg, &lines);
			printf("Loaded %d words\n", lines);
			break;
		}
	}
	if(optind != argc - 1 || !lines) {
		fprintf(stderr, "usage: %s -f <file> <iface>\n", argv[0]);
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

	char buf[MTU] = {0};
	struct beacon *template = (struct beacon *)buf;
	template->radiotap.length = 0x0008;
	template->wifi.type = 0x0080;
	memset(template->wifi.raddr, 0xff, 6);
	template->mgmt.timestamp = 0x21214489;
	template->mgmt.interval = 0x0064;
	template->mgmt.capabilities = 0x0401;

	/* inject */
	printf("beaconing on %s...\n", argv[optind]);
	while(1) {
		char *word = words[rand() % lines];
		template->essid.length = strlen(word);

		/* avoid overflows */
		if(sizeof(struct beacon) + template->essid.length > sizeof(buf))
			continue;

		/* fake but valid mac address */
		char mac[6] = {rand() & 0xfe, rand(), rand(), rand(), rand(), rand()};
		memcpy(template->wifi.saddr, mac, 6);
		memcpy(template->wifi.bssid, mac, 6);
		strcpy((char *)&template->essid.data, word);
		template->essid.length = strlen(word);
		if(!pcap_inject(pcap, template, sizeof(struct beacon) + template->essid.length))
			return 0;
		// usleep(100000);
	}
}
