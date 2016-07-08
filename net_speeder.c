// Add some rules for special use of shadowsocks.
// By Jew.07.2016


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <libnet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

#define SPECIAL_TTL 88

#ifdef COOKED
	#define ETHERNET_H_LEN 16
#else
	#define ETHERNET_H_LEN 14
#endif

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* TCP or UPD header port part*/
typedef struct tcpudp_header_port
{
     uint16_t h_sport;       /* source port */
     uint16_t h_dport;       /* destination port */
}tcpudp_header_port;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_usage(void);


/*
 * print help text
 */
void print_usage(void) {
	printf("Usage: %s [interface][\"filter rule\"]\n", "net_speeder");
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("    filter       Rules to filter packets.\n");
	printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;                  
	ip_header *ip;
	u_int ip_len;
	tcpudp_header_port *header_port;
	u_short header_sport;

	libnet_t *libnet_handler = (libnet_t *)args;
	count++;
	
	ip = (ip_header*)(packet + ETHERNET_H_LEN);
	
	/* retireve the position of the tcp header */
    	ip_len = (ip->ver_ihl & 0xf) * 4;
    	header_port = (tcpudp_header_port *) ((u_char*)ip + ip_len);
    	
    	/* convert from network byte order to host byte order */
        header_sport = ntohs( header_port->h_sport );

	if((header_sport == ss_port) && (ip->ttl != SPECIAL_TTL)) {
		ip->ttl = SPECIAL_TTL;
		int len_written = libnet_adv_write_raw_ipv4(libnet_handler, (u_int8_t *)ip, ntohs(ip->tlen));
		if(len_written < 0) {
			printf("packet len:[%d] actual write:[%d]\n", ntohs(ip->tlen), len_written);
			printf("err msg:[%s]\n", libnet_geterror(libnet_handler));
		}
	} else {
		//The packet net_speeder sent. nothing todo
	}
	return;
}

libnet_t* start_libnet(char *dev) {
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *libnet_handler = libnet_init(LIBNET_RAW4_ADV, dev, errbuf);

	if(NULL == libnet_handler) {
		printf("libnet_init: error %s\n", errbuf);
	}
	return libnet_handler;
}

#define ARGC_NUM 4
int main(int argc, char **argv) {
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_short ss_port = 0; // shadowsocks server port. set it in the argv[3].
	pcap_t *handle;

	char *filter_rule = NULL;
	struct bpf_program fp;
	bpf_u_int32 net, mask;

	if (argc == ARGC_NUM) {
		dev = argv[1];
		filter_rule = argv[2];
		ss_port = (u_short)atol(argv[3]);
		printf("Device: %s\n", dev);
		printf("Filter rule: %s\n", filter_rule);
	} else {
		print_usage();	
		return -1;
	}
	
	printf("ethernet header len:[%d](14:normal, 16:cooked)\n", ETHERNET_H_LEN);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	printf("init pcap\n");
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if(handle == NULL) {
		printf("pcap_open_live dev:[%s] err:[%s]\n", dev, errbuf);
		printf("init pcap failed\n");
		return -1;
	}

	printf("init libnet\n");
	libnet_t *libnet_handler = start_libnet(dev);
	if(NULL == libnet_handler) {
		printf("init libnet failed\n");
		return -1;
	}

	if (pcap_compile(handle, &fp, filter_rule, 0, net) == -1) {
		printf("filter rule err:[%s][%s]\n", filter_rule, pcap_geterr(handle));
		return -1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("set filter failed:[%s][%s]\n", filter_rule, pcap_geterr(handle));
		return -1;
	}

	while(1) {
		pcap_loop(handle, 1, got_packet, (u_char *)libnet_handler);
	}

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	libnet_destroy(libnet_handler);
	return 0;
}
