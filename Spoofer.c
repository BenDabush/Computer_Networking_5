#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/filter.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <pcap.h>



/* Ethernet header */
struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader
{
  unsigned char iph_ihl : 4,       // IP header length
                iph_ver : 4;       // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
                  iph_offset : 13; // Flags offset
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
  unsigned short *p_buffer = buffer;  // Declare a pointer p_buffer that points to the input buffer
  int nleft = length;  // Initialize the variable "nleft" to the length of the input buffer
  int sum = 0;  // Initialize the variable "sum" to 0
  unsigned short temp = 0;  // Declare and initialize a variable "temp" as an unsigned short with value 0
  while (nleft > 1)  // Iterate through the buffer while there are more than 1 byte left
  {
    // Add the current buffer location to the sum
    sum += *p_buffer++;
    // Decrement nleft by 2 to keep track of the number of bytes left in the buffer
    nleft -= 2;
  }

  /* 
  * If there is one byte left in the buffer, 
  * treat it as an odd byte and add it to the sum
  */
  if (nleft == 1)
  {
    // Copy the odd byte to temp
    *(u_char *)(&temp) = *(u_char *)p_buffer;
    // Add temp to the sum
    sum += temp;
  }

  /* 
  * Add back carry outs from top 16 bits to low 16 bits 
  * This allows the function to add together the upper and lower parts of the sum
  */
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





/******************************************************************
   Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int main()
{
  char buffer[1500];

  memset(buffer, 0, 1500);

  /*********************************************************
     Step 1: Fill in the ICMP header.
  ********************************************************/
  struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8; // ICMP Type: 8 is request, 0 is reply.

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
  ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
  ip->iph_destip.s_addr = inet_addr("8.8.8.8");
  ip->iph_protocol = IPPROTO_ICMP;
  ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

  /*********************************************************
     Step 3: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet(ip);

  return 0;
}
