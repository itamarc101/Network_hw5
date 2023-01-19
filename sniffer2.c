#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

FILE *file;
int count = 0;
struct ethheader
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct icmpheader
{
    unsigned char type;
    unsigned char code;
    unsigned short int checksum;
    unsigned short int id;
    unsigned short int seq;
};

struct ipheader
{
    unsigned char ip_ihl : 4;
    unsigned char ip_ver : 4;
    unsigned char ip_tos;
    unsigned short int ip_len;
    unsigned short int ip_id;
    unsigned short int ip_flag : 3;
    unsigned short int ip_offset : 13;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short int ip_checksum;
    struct in_addr source_ip;
    struct in_addr dest_ip;
};
struct newStruct
{
    uint32_t unixtime;
    uint16_t length;
    uint16_t reserved : 3, c_flag : 1, s_flag : 1, t_flag : 1, status : 10;
    uint16_t cache;
    uint16_t padding;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *device = "enp0s3";
    char *filter = "tcp or icmp";
    struct bpf_program filter_exp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    count = 0;
    file = fopen("209133826_318664190.txt", "w");

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "pcan open live error %s\n", errbuf);
        return -1;
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(handle, &filter_exp, filter, 0, net) == -1)
    {
        fprintf(stderr, "error compiling: %s\n", errbuf);
        return -1;
    }

    if (pcap_setfilter(handle, &filter_exp) == -1)
    {
        fprintf(stderr, "error setting filter: %s\n", errbuf);
        return -1;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    fclose(file);
    return 0;
}
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}
void packet_spoof(struct ipheader *ip_packet)
{
    struct sockaddr_in dest;
    int enable = 1;

    // sock creation
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1)
    {
        printf("error creating socket\n");
        return;
    }
    
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // information about dest
    dest.sin_family = AF_INET;
    dest.sin_addr = ip_packet->dest_ip;
    dest.sin_port = 0;

    ip_packet->ip_ver = 4;
    ip_packet->ip_ihl = 5;
    ip_packet->ip_ttl = 64;
    ip_packet->ip_protocol = IPPROTO_ICMP;
    ip_packet->ip_checksum = 0;
    ip_packet->ip_checksum = calculate_checksum((unsigned short *)ip_packet, sizeof(struct ipheader));

    struct icmpheader *icmp_packet = (struct icmpheader *)((unsigned char *)ip_packet + sizeof(struct ipheader));
    icmp_packet->type = 0;
    icmp_packet->checksum = 0;
    icmp_packet->checksum = calculate_checksum((unsigned short *)icmp_packet, sizeof(struct icmpheader));

    if (sendto(sock, ip_packet, ntohs(ip_packet->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest)) == -1)
        printf("error sending\n");
    else
        printf("SPOOFED PACKET!\n");
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *ether_header;
    ether_header = (struct ethheader *)packet;
    struct ipheader *ip;
    ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    switch (ip->ip_protocol)
    {

    case 1: // ICMP
        struct icmpheader *icmp_packet =(struct icmpheader*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

        if (icmp_packet->type == 8) // if type is request(8)
        {
            packet_spoof(ip);
        }
        break;

    case 6: // TCP
        struct tcphdr *tcpq;
        tcpq = (struct tcphdr *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
        struct newStruct *all;
        all = (struct newStruct *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcphdr));
        int len_of_naor = sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcphdr) + sizeof(struct newStruct);
        count++;
        if (file == NULL)
        {
            printf("Error file\n");
            return;
        }

        fprintf(file, "**********************************************************\n");
        fprintf(file, "----------------------------------------------------------\n");
        fprintf(file, "--------------------Packet-Header-------------------------\n");
        fprintf(file, "Packet Number: %d \n", count);
        fprintf(file, "Source ip address: %s \n", inet_ntoa(ip->source_ip));
        fprintf(file, "Destination ip address: %s \n", inet_ntoa(ip->dest_ip));
        fprintf(file, "Source Port: %u\n", ntohs(tcpq->th_sport));
        fprintf(file, "Destination Port: %u\n", ntohs(tcpq->th_dport));
        fprintf(file, "Timestamp: %u\n", all->unixtime);
        fprintf(file, "Total length: %u \n", all->length);
        fprintf(file, "Cache flag:  %u\n", all->c_flag);
        fprintf(file, "Steps flag: %u\n", all->s_flag);
        fprintf(file, "Type_flag: %u\n", all->t_flag);
        fprintf(file, "Status code: %u\n", all->status);
        fprintf(file, "Cache control: %u\n", all->cache);
        fprintf(file, "------------------------PAYLOAD---------------------------\n");
        for (int i = 0; i < len_of_naor; i++)
        {
            if (!(i & 15))
                fprintf(file, "\n%04X:  ", i);
            fprintf(file, "%02X ", ((unsigned char *)packet)[i]);
        }
        fprintf(file, "\n");
        fprintf(file, "----------------------------------------------------------\n");
        fprintf(file, "**********************************************************\n");
        fprintf(file, "\n");
        fprintf(file, "\n");

        break;
    }
}