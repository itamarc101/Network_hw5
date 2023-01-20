#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
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

struct udpheader
{
    u_int16_t udp_srcport;
    u_int16_t udp_destport;
    u_int16_t udp_len;
    u_int16_t udp_checksum;
};

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

void packet_spoof(struct ipheader *ip)
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
    dest.sin_addr = ip->dest_ip;
    dest.sin_port=0;

    // sends packet
    int send = sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (send == -1)
    {
        printf("error sending packet\n");
        ip->ip_ver = 4;
        ip->ip_ihl = 5;
        return;
    }
    
    printf("SUCCESSFULLY SENT A PACKET\n");
    close(sock);
}

void sendICMP()
{
    char buffer[1500];
    memset(buffer, 0, 1500);

    // FILL ICMP HEADER
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->type = 0; // 8 is request, 0 is reply

    // ICMP CHECKSUM
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmpheader));

    // FILL IP HEADER
    struct ipheader *ipp = (struct ipheader *)buffer;
    ipp->ip_ver = 4;
    ipp->ip_ihl = 5;
    ipp->ip_ttl = 20;
    ipp->source_ip.s_addr = inet_addr("72.27.72.27");
    ipp->dest_ip.s_addr = inet_addr("8.8.8.8");
    ipp->ip_protocol = IPPROTO_ICMP;
    ipp->ip_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
    packet_spoof(ipp);

}

void sendUDP()
{
    char bufUDP[1500];
    memset(bufUDP, 0, 1500);

    // FILL UDP
    struct ipheader *ipp = (struct ipheader *)bufUDP;
    struct udpheader *udp = (struct udpheader *)(bufUDP + sizeof(struct ipheader));
    char *data = bufUDP + sizeof(struct ipheader) + sizeof(struct udpheader);
    const char *msg = "This is UDP\n";
    int msgln = strlen(msg);
    strncpy(data,msg,msgln);


    udp->udp_srcport = htons(1234);
    udp->udp_destport = htons(4321);
    udp->udp_len = htons(sizeof(struct udpheader) + msgln);
    udp->udp_checksum = 0;
    ipp->ip_ver = 4;
    ipp->ip_ihl = 5;
    ipp->ip_ttl = 20;
    ipp->source_ip.s_addr=inet_addr("27.27.72.72");
    ipp->dest_ip.s_addr=inet_addr("72.72.27.27");
    // SENDS UDP SPOOF //
    ipp->ip_protocol = IPPROTO_UDP;
    ipp->ip_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader)+msgln);
    packet_spoof(ipp);

}

int main()
{
    sendICMP();
    //sendUDP();
    return 0;
}
