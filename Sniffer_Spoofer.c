#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/filter.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>


struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};
/* ICMP Header  */
struct icmpheader
{
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error code
  unsigned short int icmp_chksum; // Checksum for ICMP Header and data
  unsigned short int icmp_id;     // Used for identifying request
  unsigned short int icmp_seq;    // Sequence number
};

/**
 * This function calculates a checksum for a given buffer of data.
 * The input parameters are a pointer to an unsigned short buffer and the length of the buffer.
*/
unsigned short in_cksum(unsigned short *buffer, int length)
{
  unsigned short *p_buffer = buffer; 
  int nleft = length;
  int sum = 0;
  unsigned short temp = 0;
  while (nleft > 1) 
  {
    // Add the current buffer location to the sum
    sum += *p_buffer++;
    // Decrement nleft by 2 to keep track of the number of bytes left in the buffer
    nleft -= 2;
  }
  if (nleft == 1)
  {
    // Copy the odd byte to temp
    *(u_char *)(&temp) = *(u_char *)p_buffer;
    // Add temp to the sum
    sum += temp;
  }
  sum = (sum >> 16) + (sum & 0xffff); 
  // Add carry
  sum += (sum >> 16);
  // Return the two's complement of the sum as the final checksum
  return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader *ip)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("got_packet !!\n");

    char buffer[1500];
    memset(buffer, 0, 1500);
    memcpy(buffer, packet, sizeof(buffer));
    char temp_source_ip[INET_ADDRSTRLEN] = "0.0.0.0";

    /*********************************************************
     Step 1: Fill in the ICMP header.
    ********************************************************/
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 0; // ICMP Type: 8 is request, 0 is reply.

    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = (unsigned short)in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

    /*********************************************************
     Step 2: Fill in the IP header.
    ********************************************************/
    struct ipheader *ip = (struct ipheader *)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    inet_ntop(AF_INET, &ip->iph_sourceip, temp_source_ip, INET_ADDRSTRLEN);
    ip->iph_sourceip.s_addr = ip->iph_destip.s_addr;
    inet_pton(AF_INET, temp_source_ip, &ip->iph_destip);
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    /*********************************************************
     Step 3: Finally, send the spoofed packet
    ********************************************************/
    send_raw_ip_packet(ip);
}

int main()
{
    printf("let's Gooo!!!!\n");
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  // ip addrr 127.0.0.1
  bpf_u_int32 net;
  printf("The problem is in pcap_open_live?\n");
  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 
  printf("No :)\n");
printf("The problem is in pcap compile?\n");
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  printf("No :)\n");      
  printf("The problem is in pcap setfillter?\n");
  pcap_setfilter(handle, &fp);                             
  printf("No :)\n");
  printf("The problem is in pacp loop?\n");
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                
  printf("No :)\n");
  pcap_close(handle);   //Close the handle 
  return 0;
}