#include <stdio.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

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

struct ethheader
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

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

    // sends packet
    int send = sendto(sock, ip_packet, ntohs(ip_packet->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (send == -1)
    {
        printf("error sending packet\n");
        ip_packet->ip_ver = 4;
        ip_packet->ip_ihl = 5;
        return;
    }

    printf("SUCCESSFULLY SENT A PACKET\n");
    close(sock);
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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *ether_packet = (struct ethheader *)packet;
    struct ipheader *ip_packet;
    ip_packet = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct icmpheader *icmp_packet = (struct icmpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

    //if (icmp_packet->type == 8) // if type is request(8)
    //{ 

        printf("SEND IT\n");
        char buf[1500];
        memset((char *)buf, 0, 1500);
        memcpy((char *)buf, ip_packet, ntohs(ip_packet->ip_len));

        struct ipheader *ip_spoof = (struct ipheader *)buf;
        struct icmpheader *icmp_spoof = (struct icmpheader *)(buf + sizeof(struct ipheader));
        icmp_spoof->type = 0; // set packet to be reply(0)

        ip_spoof->source_ip = ip_packet->dest_ip;
        ip_spoof->dest_ip = ip_packet->source_ip;
        ip_spoof->ip_checksum = 0;
        icmp_spoof->checksum = 0;
        ip_spoof->ip_checksum = (calculate_checksum((unsigned short *)ip_spoof, sizeof(struct ipheader)));
        icmp_spoof->checksum = (calculate_checksum((unsigned short *)icmp_spoof, sizeof(struct icmpheader)));

        packet_spoof(ip_spoof);
    //}
}
int main(int argc, char *argv[])
{
    printf("Start\n");
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *device = "enp0s3";
    char *filter = "icmp[icmptype] = icmp-echo";
    struct bpf_program filter_exp;
    bpf_u_int32 net;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "pcan open live error %s\n", errbuf);
        return -1;
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
    printf("hiii\n");
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
