#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <time.h>

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
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
        printf("got_packet !!/n");

    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    printf("new message\n");
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("       To: %s\n", inet_ntoa(ip->iph_destip));
    }
    
    struct ether_header *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    FILE *fp;
    fp = fopen("318607314_316014760.txt", "a");

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

    if (ip_header->protocol != IPPROTO_TCP)
    {
        return;
    }

    tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    fprintf(fp, "{ source_ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %ld, total_length: %d, cache_flag: %d, steps_flag: %d,type_flag: %d, status_code: %d, cache_control: %d, data: ", source_ip, dest_ip, ntohs(tcp_header->source), ntohs(tcp_header->dest), header->ts.tv_sec, header->len, 0, 0, 0, 0, 0);
    
    for (int i = 0; i < header->len; i++)
    {
        fprintf(fp, "%02x ", packet[i]);
    }
    fprintf(fp, "}\n");
    fclose(fp);
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp port 9999";
  // ip addrr 127.0.0.1
  bpf_u_int32 net = 0;
  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
// int main()
// {
//     printf("1\n");
//     char *dev;
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t *handle;
//     struct bpf_program fp;
//     char filter_exp[] = "ip proto icmp";
//     bpf_u_int32 mask;
//     bpf_u_int32 net;

//     pcap_if_t *alldevs;
//     pcap_findalldevs(&alldevs, errbuf);
//     dev = alldevs->name;
//     if (dev == NULL)
//     {
//         fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
//         return (2);
//     }
//     if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
//     {
//         fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
//         net = 0;
//         mask = 0;
//     }
//     printf("2\n");
//     handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//     if (handle == NULL)
//     {
//         fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
//         return (2);
//     }
//     if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
//     {
//         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
//         return (2);
//     }
//     if (pcap_setfilter(handle, &fp) == -1)
//     {
//         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
//         return (2);
//     }
//     printf("3\n");

//     pcap_loop(handle, -1, got_packet, NULL);
//         printf("4\n");

//     pcap_freecode(&fp);
//     printf("5\n");

//     pcap_freealldevs(alldevs);
//     printf("6\n");

//     pcap_close(handle);
//     return (0);
// }