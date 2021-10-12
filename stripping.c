#include <stdio.h>
#include <stdint.h>
#include <time.h>

typedef struct pcap_file_header_s {
	uint32_t magic_number;	// 0xa1b2c3d4
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;	// 0
	uint32_t snaplen;
	uint32_t network;
} pcap_file_header_t;

typedef struct timeval {
	uint32_t sec;
	uint32_t usec;
} timeval;

typedef struct pcap_packet_header_s {
	struct timeval ts;
	uint32_t caplen;
	uint32_t len;
} pcap_packet_header_t;

typedef struct ethernet_s {
	unsigned char destMAC[6];
	unsigned char srcMAC[6];
	unsigned short type;
} ethernet_t;

typedef struct ip_s {
	unsigned char hlen : 4;
	unsigned char version : 4;
	unsigned char service;
	unsigned short total_len;
	unsigned short id;
	unsigned short frags;	// FLAGS(3) + Fragmentation offset(13)
	unsigned char TTL;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int srcIP;
	unsigned int destIP;
} ip_t;

unsigned short change_endian(unsigned short value) {
	return (value << 8) | (value >> 8);
}

void printMAC(unsigned char *add) {
	for (int i = 0; i < 5; i++)
		printf("%02x:", add[i]);
	printf("%02x\n", add[5]);
}

void printIP(unsigned int add) {
	unsigned char *IP = (unsigned char *)&add;
	for (int i = 0; i < 3; i++)
		printf("%d.", IP[i]);
	printf("%d\n", IP[3]);
}

void ViewIP(char *buf) {
	ip_t *ip = (ip_t *)buf;

	printf("** IP header **\n");
	printf("  version : %d\n", ip->version);
	printf("  header length : %d (%d bytes)\n", ip->hlen, ip->hlen * 4);
	printf("  Total length : %d\n", change_endian(ip->total_len));

	printf("  Source IP address : ");
	printIP(ip->srcIP);
	printf("  Destination IP address : ");
	printIP(ip->destIP);

	// fragmentation
	printf("  Identification : 0x%x\n", change_endian(ip->id));
	printf("    Identificaion in decimal : %d\n", change_endian(ip->id));
	printf("  Flags : 0x%x\n", ip->frags);
	// DF
	if (ip->frags & 0x40)
		printf("    Don't Fragment : set\n");
	else
		printf("    Don't Fragment : Not set\n");
	// MF
	if (ip->frags & 0x20)
		printf("    More Fragment : set\n");
	else
		printf("    More Fragment : Not set\n");

	// TTL
	printf("  Time to live : %d\n", ip->TTL);

	// protocol
	printf("  Protocol : ");
	switch (ip->protocol) {
		case 1: printf("ICMP\n"); break;
		case 2: printf("IGMP\n"); break;
		case 6: printf("TCP\n"); break;
		case 17: printf("UDP\n"); break;
		default: printf("%d\n", ip->protocol); break;
	}
}

void ViewEthernet(char *buf) {
	ethernet_t *eth = (ethernet_t *)buf;

	printf("** Ethernet **\n");
	printf("  Source MAC address : ");
	printMAC(eth->srcMAC);
	printf("  Destination MAC address : ");
	printMAC(eth->destMAC);

	if (change_endian(eth->type) == 0x800){
		ViewIP(buf + sizeof(ethernet_t));
	}
	else if (change_endian(eth->type) == 0x0806)
		printf("  Type : ARP\n");
}

void ParsingPacket(FILE *fp) {
	int count = 0;

	while (!feof(fp)) {
		pcap_packet_header_t packet_h;
		char buf[65536];
		if (fread(&packet_h, sizeof(packet_h), 1, fp) != 1)
			break;

		count++;
		printf("===== Packet %d =====\n", count);
		time_t timeinfo = (time_t)packet_h.ts.sec;
		struct tm *t = (struct tm *)localtime(&timeinfo);
		printf("local time : %d:%d:%d.%u\n", t->tm_hour, t->tm_min, t->tm_sec, packet_h.ts.usec);
		printf("capture length : %u\n", packet_h.caplen);
		printf("actual length : %u\n", packet_h.len);
		fread(buf, packet_h.caplen, 1, fp);

//		PacketData(buf);
		ViewEthernet(buf);
		printf("\n");
		if (count % 100 == 0) {
			int n;
			scanf("%d", &n);
		}
	}

	printf("Total packets : %d\n", count);
}

void Parsing(FILE *fp) {
	pcap_file_header_t file_h;
	fread(&file_h, sizeof(file_h), 1, fp);	// file information 읽기

	// magic number check
	if (file_h.magic_number != 0xa1b2c3d4) {
		printf("Magic number is not correct\n");
		return;
	}

	// file informations
//	printf("version : %u / %u\n", file_h.version_major, file_h.version_minor);
//	printf("sigfigs : %u\n", file_h.sigfigs);
//	printf("snaplen : %u\n", file_h.snaplen);
//	printf("network : %u\n", file_h.network);

	ParsingPacket(fp);
}

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("파싱할 파일을 함께 입력하세요\n");
		return 0;
	}
	FILE *fp = fopen(argv[1], "rb");	// binary mode로 file open
	Parsing(fp);
	fclose(fp);
	return 0;
}
