#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>

typedef struct pcap_hdr_s {
	uint32_t magic_number;	// 0xa1b2c3d4
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;	// 0
	uint32_t snaplen;
	uint32_t network;
} pcap_hdr_t;

typedef struct time_val {
	uint32_t sec;
	uint32_t usec;
} time_val;

typedef struct pcaprec_hdr_s {
	struct time_val ts;
	uint32_t caplen;
	uint32_t len;
} pcaprec_hdr_t;

typedef struct ethernet_s {
	unsigned char destMAC[6];
	unsigned char srcMAC[6];
	uint16_t type;
} ethernet_t;

typedef struct ipv4_s {
	unsigned char hlen : 4;
	unsigned char version : 4;
	unsigned char service;
	uint16_t total_len;
	uint16_t id;
	uint16_t frags;	// FLAGS(3) + Fragmentation offset(13)
	unsigned char TTL;
	unsigned char protocol;
	uint16_t checksum;
	uint32_t srcIP;
	uint32_t destIP;
} ipv4_t;

typedef struct tcp_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seqno;
	uint32_t ackno;
	unsigned char hlen_res;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char reserved : 2;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_pointer;
} tcp_t;

typedef struct udp_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t total_len;
	uint16_t checksum;
} udp_t;

int max_tcp;
int max_udp;

unsigned short ntoh_s(unsigned short value) {
	return (value << 8) | (value >> 8);
}

unsigned int ntoh_l(unsigned int value) {
	return ((value & 0x000000ff) << 24) | 
			((value & 0x0000ff00) << 8) | 
			((value & 0x00ff0000) >> 8) | 
			((value & 0xff000000) >> 24);
}

void ParseTCPOptions(char *buf, int option_len) {
	int i = 0;

	while (i < option_len) {
		if (buf[i] == 0) {
			printf("	End of Options\n");
			break;
		}
		else if (buf[i] == 1) {	// for padding
			printf("	No operation\n");
			i++;
		}
		else if (buf[i] == 2) {
			int mss = (unsigned char)buf[i + 2] * 16 * 16 + (unsigned char)buf[i + 3];
			printf("	Maximum segment size : %d\n", mss);
			i += 4;
		}
		else if (buf[i] == 3) {
			printf("	Window scale : %d\n", buf[i + 2]);
			i += 3;
		}
		else if (buf[i] == 4) {
			printf("	SACK permitted\n");
			i += 2;
		}
		else if (buf[i] == 5) {
			printf("	SACK\n");
			i += buf[i + 1];
		}
		else if (buf[i] == 8) {
			printf("	Timestamp\n");
			i += 10;
		}
		else if (buf[i] == 28) {
			printf("	User Timeout\n");
			i += 4;
		}
		else if (buf[i] == 29) {
			printf("	TCP-AO\n");
			i += buf[i + 1];
		}
		else {
			i += buf[i + 1];
		}
	}
}

void ApplicationType(uint16_t port) {
	switch (port)
	{
	case 1:
		printf("  Application Type : TCPMUX\n");
		break;
	case 7:
		printf("  Application Type : ECHO\n");
		break;
	case 13:
		printf("  Application Type : DAYTIME\n");
		break;
	case 20:
		printf("  Application Type : FTP\n");
		break;
	case 21:
		printf("  Application Type : FTP\n");
		break;
	case 22:
		printf("  Application Type : SSH\n");
		break;
	case 23:
		printf("  Application Type : TELNET\n");
		break;
	case 25:
		printf("  Application Type : SMTP\n");
		break;
	case 53:
		printf("  Application Type : DNS\n");
		break;
	case 67:
		printf("  Application Type : DHCP\n");
		break;
	case 68:
		printf("  Application Type : DHCP\n");
		break;
	case 80:
		printf("  Application Type : HTTP\n");
		break;
	case 123:
		printf("  Application Type : NTP\n");
		break;
	case 179:
		printf("  Application Type : BGP\n");
		break;
	case 443:
		printf("  Application Type : HTTPS\n");
		break;
	default:
		break;
	}
}

void ParseTCP(char *buf, ipv4_t *ip) {
	tcp_t *tcp = (tcp_t *)buf;

	// payload size
	int hlen = (tcp->hlen_res >> 4) * 4;
	int16_t payload_size = ntoh_s(ip->total_len) - (ip->hlen * 4 + hlen);
	if (payload_size > max_tcp)
		max_tcp = payload_size;

	printf("** TCP header **\n");
	printf("  Source Port : %u\n", ntoh_s(tcp->src_port));
	printf("  Destination Port : %u\n", ntoh_s(tcp->dst_port));
	// Starting sequence number and ending sequence number if the TCP payload exist
	if (payload_size) {
		printf("  Sequence number (raw) : %u  ~  %u\n", ntoh_l(tcp->seqno), ntoh_l(tcp->seqno) + payload_size - 1);
		printf("  [ Next Sequence number : %u ]\n", ntoh_l(tcp->seqno) + payload_size);
	}
	else
		printf("  Sequence number (raw) : %u\n", ntoh_l(tcp->seqno));
	printf("  Acknowledgment number (raw) : %u\n", ntoh_l(tcp->ackno));
	printf("  TCP Payload size : %d bytes\n", payload_size);
	printf("  Flags :");
	if (tcp->urg)
		printf(" URG");
	if (tcp->ack)
		printf(" ACK");
	if (tcp->psh)
		printf(" PSH");
	if (tcp->rst)
		printf(" RST");
	if (tcp->syn)
		printf(" SYN");
	if (tcp->fin)
		printf(" FIN");
	printf("\n");
	printf("  Window size : %u\n", ntoh_s(tcp->window));
	// TCP options
	if (hlen > 20) {
		printf("  * TCP options : %d bytes *\n", hlen - 20);
		ParseTCPOptions(buf + 20, hlen - 20);
	}
	uint16_t portNum = (tcp->src_port < 1024) ? ntoh_s(tcp->src_port) : ntoh_s(tcp->dst_port);
	ApplicationType(portNum);
}

void ParseUDP(char *buf, ipv4_t *ip) {
	udp_t *udp = (udp_t *)buf;

	printf("** UDP header **\n");
	printf("  Source Port : %u\n", ntoh_s(udp->src_port));
	printf("  Destination Port : %u\n", ntoh_s(udp->dst_port));

	// payload size
	int payload_size = ntoh_s(udp->total_len) - 8;
	printf("  UDP Payload size : %d bytes\n", payload_size);
	if (payload_size > max_udp)
		max_udp = payload_size;
	uint16_t portNum = (udp->src_port < 1024) ? ntoh_s(udp->src_port) : ntoh_s(udp->dst_port);
	ApplicationType(portNum);
}

void ParseIP(char *buf) {
	ipv4_t *ip = (ipv4_t *)buf;

	printf("The length in IP header : %u\n", ntoh_s(ip->total_len));
	switch (ip->protocol)
	{
	case 6:
		ParseTCP(buf + ip->hlen * 4, ip);
		break;
	case 17:
		ParseUDP(buf + ip->hlen * 4, ip);
		break;
	default:
		printf("Neither TCP nor UDP\n");
		break;
	}
}

void ParseEthernet(char *buf) {
	ethernet_t *eth = (ethernet_t *)buf;

	if (ntoh_s(eth->type) == 0x800)
		ParseIP(buf + sizeof(ethernet_t));
	else if (ntoh_s(eth->type) == 0x0806)
		printf("Type : ARP\n");
}

void ParsingPacket(FILE *fp) {
	int count = 0;

	while (!feof(fp)) {
		pcaprec_hdr_t packet_h;
		char buf[65536];
		if (fread(&packet_h, sizeof(packet_h), 1, fp) != 1)
			break;

		count++;		
		printf("===== Packet %d =====\n", count);
		time_t timeinfo = (time_t)packet_h.ts.sec;
		struct tm *t = (struct tm *)localtime(&timeinfo);
		printf("local time : %d:%d:%d.%.6u\n", t->tm_hour, t->tm_min, t->tm_sec, packet_h.ts.usec);
		printf("capture length : %u\n", packet_h.caplen);
		printf("actual length : %u\n", packet_h.len);
		fread(buf, packet_h.caplen, 1, fp);

		ParseEthernet(buf);
		printf("\n");
	}

	printf("Total packets : %d\n", count);
	printf("The greatest payload size of TCP : %d\n", max_tcp);
	printf("The greatest payload size of UDP : %d\n", max_udp);
}


void Parsing(FILE *fp) {
	pcap_hdr_t file_h;
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
		printf("ERROR: 파싱할 파일을 함께 입력하세요\n");
		return 0;
	}
	FILE *fp = fopen(argv[1], "rb");	// binary mode로 file open
	Parsing(fp);
	fclose(fp);
	return 0;
}

