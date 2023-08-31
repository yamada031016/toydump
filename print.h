#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>

char *my_ether_ntoa_r(unsigned char *hwaddr, char *buf, socklen_t size);
char *arp_ip2str(u_int8_t *ip, char *buf, socklen_t size);
char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int printEtherHeader(struct ether_header *eh, FILE *fp);
int printArp(struct ether_arp *arp, FILE *fp);
int printIpHeader(struct iphdr *iphdr, unsigned char *option, int optionLen,
                  FILE *fp);
int printIp6Header(struct ip6_hdr *ip6, FILE *fp);
int printIcmp(struct icmp *icmp, FILE *fp);
int printIcmp6(struct icmp6 *icmp6_hdr, FILE *fp);
int printTcp(struct tcphdr *tcphdr, FILE *fp);
int printUdp(struct udphdr *udphdr, FILE *fp);
