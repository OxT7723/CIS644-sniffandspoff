/*****************************************************************
*********** 	Lab 2 Task 3 ******************
* Name:		Teddie Davis
* Email:	tdavis08@syr.edu
* Started off with the base code from sniffex and made changes
* to the program where needed to make it sniff and then spoof for only ICMP
******************************************************************/

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h> //gets IP header 

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/*
Pulled from checksum.c file - the checksum.c file linked to the myheader.h file.
With the myheader.h file and using the includes for <netinet/ip_icmp.h> ran into issues.
*/
unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}


/* ICMP Header changed some of the nameing to keep from running into issues from the #include <netinet/ip_icmp.h> */
struct myicmpheader {
	unsigned char icmp_type;				//ICMP message type
	unsigned char icmp_code;				//Error code
	unsigned short int icmp_chksum;			//Checksum for ICMP Header and data
	unsigned short int icmp_id_;			//Used in echo request/reply to identify request
	unsigned short int icmp_seq_;			//Identifies the sequence of echo messages, 
											//if more than one is sent
};

//THe ipheader from the myheader.h file
struct ipheader {
	unsigned char      iph_ihl : 4, iph_ver : 4;		//IP Header length & Version.
	unsigned char      iph_tos;							//Type of service
	unsigned short int iph_len;							//IP Packet length (Both data and header)
	unsigned short int iph_ident;						//Identification
	unsigned short int iph_flag : 3, iph_offset : 13;	//Flags and Fragmentation offset
	unsigned char      iph_ttl;							//Time to Live
	unsigned char      iph_protocol;					//Type of the upper-level protocol
	unsigned short int iph_chksum;						//IP datagram checksum
	struct  in_addr    iph_sourceip;					//IP Source address (In network byte order)
	struct  in_addr    iph_destip;						//IP Destination address (In network byte order)
};

/* IP header used for sniffing by sniffex */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header for sniffing by sniffex */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};


void
got_packet_now_spoof_it(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
spoof_icmp_reply(struct ipheader* ip);

void
print_app_banner(void);

void
print_app_usage(void);

/*
* app name/banner
*/
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

	return;
}

/*
* print help text
*/
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

	return;
}

/*
* print data in rows of 16 bytes: offset   hex   ascii
*
* 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
*/
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

//takes the packet sent from pcap
void got_packet_now_spoof_it(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	struct sniff_ethernet *eth = (struct sniff_ethernet *)packet;
	//struct ethheader *eth = (struct ethheader *)packet;
	if (eth->ether_type != ntohs(0x0800)) return; // not an IP packet check

												  //creating an new pointer to hold the packet info with casting it to the struct type of ipheader
	struct ipheader* ip = (struct ipheader*)(packet + SIZE_ETHERNET);

	//setting the lenth of the ip header
	int ip_header_len = ip->iph_ihl * 4;


	//printf("------------------\n");
	//printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
	//printf("         To: %s\n", inet_ntoa(ip->iph_destip));

	//check the protocol to make sure it's ICMP
	if (ip->iph_protocol == IPPROTO_ICMP) {
		printf("      Got an ICMP packet \n");
		spoof_icmp_reply(ip);
	}

	return;
}

//takes an ip packet and sends it using a raw socket
void send_raw_ip_packet(struct ipheader* ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;

	//Create a raw network socket, and set its options.
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	//Provide needed information about destination.
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	printf("Sending a fake response\n");

	// send the packet out.
	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);

}

// taking the ipheader that will be copied and changed to be an echo reply
void spoof_icmp_reply(struct ipheader* ip)
{
	//setting the ip header lenth 
	int ip_header_len = ip->iph_ihl * 4;
	const char buffer[SNAP_LEN]; //sentting the buffer size

	struct myicmpheader* icmp = (struct myicmpheader *)((u_char *)ip + ip_header_len);
	if (icmp->icmp_type != 8)
	{
		printf("Not an echo Request\n");
		return;
	}

	//getting some memory  
	memset((char*)buffer, 0, SNAP_LEN);

	//making a copy of the incoming packet
	memcpy((char*)buffer, ip, ntohs(ip->iph_len));
	struct ipheader * newip = (struct ipheader *) buffer;
	struct myicmpheader * newicmp = (struct myicmpheader *) ((u_char *)buffer + ip_header_len);

	//swaping the src and dest in faked ICMP packet
	newip->iph_sourceip = ip->iph_destip;
	newip->iph_destip = ip->iph_sourceip;

	newip->iph_ttl = 20; //setting the time to live
	newip->iph_protocol = IPPROTO_ICMP;	//setting the protocol

										// setting the type to 0 for an echo reply
	newicmp->icmp_type = 0;

	//Calculate the checksum for integrity. ICMP checksum includes the data. 
	newicmp->icmp_chksum = 0;
	newicmp->icmp_chksum = in_cksum((unsigned short*)newicmp, ntohs(ip->iph_len) - ip_header_len);

	// now take our new packet and send it off to be sent by using a raw socket
	send_raw_ip_packet(newip);
}



int main(int argc, char **argv)
{

	char *dev = NULL;					/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;						/* packet capture handle */

	char filter_exp[] = "icmp[icmptype]=icmp-echo";		/* filter expression [3] */ //changed so that we would only get icmp types

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
								//	int num_packets = 10;			/* number of packets to capture */
	int num_packets = -1; // just keep getting packets

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
				errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */ //3rd pram trun on or off promiscuous mode.
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	//pointed to my function called got_packet_now_spoof_it
	pcap_loop(handle, num_packets, got_packet_now_spoof_it, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}
