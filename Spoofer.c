#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

unsigned short checksum(unsigned short *buf, int size) {
  unsigned long sum = 0;
  while(size > 1) {
      sum += *buf++;
      size -= 2;
  }
  if(size) sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

int main(int argc, char *argv[]) {
  if(argc < 2) {
    printf("Usage: %s <destination IP>\n", argv[0]);
    exit(1);
  }

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(sockfd < 0) {
    perror("socket");
    exit(1);
  }

  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(argv[1]);

  char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + 64];
  memset(packet, 0, sizeof(packet));

  struct iphdr *ip = (struct iphdr *) packet;
  struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = sizeof(packet);
  ip->id = htons(rand());
  ip->frag_off = 0;
  ip->ttl = 255;
  ip->protocol = IPPROTO_ICMP;
  ip->check = 0;
  ip->saddr = inet_addr("127.0.0.1");
  ip->daddr = dest_addr.sin_addr.s_addr;

  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->checksum = 0;
  icmp->un.echo.id = 0;
  icmp->un.echo.sequence = 0;

  char *data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));

  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->checksum = 0;
  icmp->un.echo.id = htons(random());
  icmp->un.echo.sequence = htons(0);

  // Fill in payload data
  int i;
  for(i = 0; i < 64; i++)
      *(data + i) = i;

  icmp->checksum = checksum((unsigned short *) icmp, sizeof(struct icmphdr) + 64);

  if(sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0) {
      perror("sendto");
      exit(1);
  } else {
      printf("ICMP echo request packet sent to %s\n", argv[1]);
  }

  close(sockfd);
  return 0;
}






















































// /**********************************************
//  * Listing 12.5: Send out spoofed IP packet
// **********************************************/

// /**********************************************
//  * Listing 12.6: Constructing raw ICMP echo request packet
// **********************************************/
// #include <stdio.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <netinet/ip.h>

// /* ICMP Header  */
// struct icmpheader {
//   unsigned char icmp_type; // ICMP message type
//   unsigned char icmp_code; // Error code
//   unsigned short int icmp_chksum; //Checksum for ICMP Header and data
//   unsigned short int icmp_id;     //Used for identifying request
//   unsigned short int icmp_seq;    //Sequence number
// };

// /*************************************************************
//   Given an IP packet, send it out using a raw socket. 
// **************************************************************/
// void send_raw_ip_packet(struct ipheader* ip)
// {
//   struct sockaddr_in dest_info;
//   int enable = 1;

//   // Step 1: Create a raw network socket.
//   int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

//   // Step 2: Set socket option.
//   setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

//   // Step 3: Provide needed information about destination.
//   dest_info.sin_family = AF_INET;
//   dest_info.sin_addr = ip->iph_destip;

//   // Step 4: Send the packet out.
//   sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
//   close(sock);
// }




// /******************************************************************
//   Spoof an ICMP echo request using an arbitrary source IP Address
// *******************************************************************/
// int main() {
//   char buffer[1500];

//   memset(buffer, 0, 1500);

//   /*********************************************************
//     Step 1: Fill in the ICMP header.
//   ********************************************************/
//   struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
//   icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

//   // Calculate the checksum for integrity
//   icmp->icmp_chksum = 0;
//   icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

//   /*********************************************************
//     Step 2: Fill in the IP header.
//   ********************************************************/
//   struct ipheader *ip = (struct ipheader *) buffer;
//   ip->iph_ver = 4;
//   ip->iph_ihl = 5;
//   ip->iph_ttl = 20;
//   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
//   ip->iph_destip.s_addr = inet_addr("10.0.2.5");
//   ip->iph_protocol = IPPROTO_ICMP; 
//   ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

//   /*********************************************************
//     Step 3: Finally, send the spoofed packet
//   ********************************************************/
//   send_raw_ip_packet (ip);

//   return 0;
// }







































































// #include <stdio.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <netinet/ip.h>
// #include <pcap.h>
// #include <arpa/inet.h>
// #include <errno.h>
// // #include <netinet/ip_icmp.h>
// #include <netinet/in.h>
// #include <stdlib.h>
// #include <sys/types.h>
// #include <unistd.h>

// /**********************************************
//  * Listing 12.4: Get captured packet
//  **********************************************/
// /* IP Header */
// struct ipheader
// {
//   unsigned char iph_ihl : 4,       // IP header length
//       iph_ver : 4;                 // IP version
//   unsigned char iph_tos;           // Type of service
//   unsigned short int iph_len;      // IP Packet length (data + header)
//   unsigned short int iph_ident;    // Identification
//   unsigned short int iph_flag : 3, // Fragmentation flags
//       iph_offset : 13;             // Flags offset
//   unsigned char iph_ttl;           // Time to Live
//   unsigned char iph_protocol;      // Protocol type
//   unsigned short int iph_chksum;   // IP datagram checksum
//   struct in_addr iph_sourceip;     // Source IP address
//   struct in_addr iph_destip;       // Destination IP address
// };

// /**********************************************
//  * Listing 12.6: Constructing raw ICMP echo request packet
//  **********************************************/
// /* ICMP Header  */
// struct icmpheader
// {
//   unsigned char icmp_type;        // ICMP message type
//   unsigned char icmp_code;        // Error code
//   unsigned short int icmp_chksum; // Checksum for ICMP Header and data
//   unsigned short int icmp_id;     // Used for identifying request
//   unsigned short int icmp_seq;    // Sequence number
// };

// int createAndSendICMPmsg(char buffer[1500])
// {

//   /*********************************************************
//     Step 1: Fill in the ICMP header.
//   ********************************************************/
//   struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
//   icmp->icmp_type = 8; // ICMP Type: 8 is request, 0 is reply.

//   // Calculate the checksum for integrity
//   icmp->icmp_chksum = 0;
//   icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
// }

// int main()
// {
//   char buffer[1500];

//   memset(buffer, 0, 1500);


//   struct ipheader* ip;

//    /*********************************************************
//       Step 2: Fill in the IP header.
//     ********************************************************/
//    struct ipheader *ip = (struct ipheader *) buffer;

//    ip->iph_ver = 4;
//    ip->iph_ihl = 5;
//    ip->iph_ttl = 20;
//    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4"); //fake iph_sourceip
//    ip->iph_destip.s_addr = inet_addr("8.8.8.8");
//    ip->iph_protocol = IPPROTO_ICMP;
//    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));



//   // Step 1: Create a raw network socket.
//   int sock = -1;
//   if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
//   {
//     fprintf(stderr, "socket() failed with error: %d", errno);
//     fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
//     return -1;
//   }
//   struct sockaddr_in dest_info;
//   int enable = 1;

//   // Step 2: Set socket option.
//   setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

//   // Step 3: Provide needed information about destination.
//   dest_info.sin_family = AF_INET;
//   dest_info.sin_addr = ip->iph_destip;

//   // Step 4: Send the packet out.
//   sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
//   close(sock);
// }

// // /**********************************************
// //  * Listing 12.4: Get captured packet
// //  **********************************************/
// // /* IP Header */
// // struct ipheader {
// //   unsigned char      iph_ihl:4, //IP header length
// //                      iph_ver:4; //IP version
// //   unsigned char      iph_tos; //Type of service
// //   unsigned short int iph_len; //IP Packet length (data + header)
// //   unsigned short int iph_ident; //Identification
// //   unsigned short int iph_flag:3, //Fragmentation flags
// //                      iph_offset:13; //Flags offset
// //   unsigned char      iph_ttl; //Time to Live
// //   unsigned char      iph_protocol; //Protocol type
// //   unsigned short int iph_chksum; //IP datagram checksum
// //   struct  in_addr    iph_sourceip; //Source IP address
// //   struct  in_addr    iph_destip;   //Destination IP address
// // };

// // /**********************************************
// //  * Listing 12.6: Constructing raw ICMP echo request packet
// //  **********************************************/
// // /* ICMP Header  */
// // struct icmpheader {
// //   unsigned char icmp_type; // ICMP message type
// //   unsigned char icmp_code; // Error code
// //   unsigned short int icmp_chksum; //Checksum for ICMP Header and data
// //   unsigned short int icmp_id;     //Used for identifying request
// //   unsigned short int icmp_seq;    //Sequence number
// // };

// // /*************************************************************
// //   Given an IP packet, send it out using a raw socket.
// // **************************************************************/
// // void send_raw_ip_packet(struct ipheader* ip)
// // {
// //     struct sockaddr_in dest_info;
// //     int enable = 1;

// //     // Step 1: Create a raw network socket.
// //     int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

// //     // Step 2: Set socket option.
// //     setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
// //                      &enable, sizeof(enable));

// //     // Step 3: Provide needed information about destination.
// //     dest_info.sin_family = AF_INET;
// //     dest_info.sin_addr = ip->iph_destip;

// //     // Step 4: Send the packet out.
// //     sendto(sock, ip, ntohs(ip->iph_len), 0,
// //            (struct sockaddr *)&dest_info, sizeof(dest_info));
// //     close(sock);
// // }

// // int main() {
// //    char buffer[1500];

// //    memset(buffer, 0, 1500);

// //    /*********************************************************
// //       Step 1: Fill in the ICMP header.
// //     ********************************************************/
// //    struct icmpheader *icmp = (struct icmpheader *)
// //                              (buffer + sizeof(struct ipheader));
// //    icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

// //    // Calculate the checksum for integrity
// //    icmp->icmp_chksum = 0;
// //    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
// //                                  sizeof(struct icmpheader));

// //    /*********************************************************
// //       Step 2: Fill in the IP header.
// //     ********************************************************/
// //    struct ipheader *ip = (struct ipheader *) buffer;
// //    ip->iph_ver = 4;
// //    ip->iph_ihl = 5;
// //    ip->iph_ttl = 20;
// //    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
// //    ip->iph_destip.s_addr = inet_addr("10.0.2.5");
// //    ip->iph_protocol = IPPROTO_ICMP;
// //    ip->iph_len = htons(sizeof(struct ipheader) +
// //                        sizeof(struct icmpheader));

// //    /*********************************************************
// //       Step 3: Finally, send the spoofed packet
// //     ********************************************************/
// //    send_raw_ip_packet (ip);

// //    return 0;
// // }
