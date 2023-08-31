#include "checksum.h"
#include "print.h"
#include <arpa/inet.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

int analyzeArp(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct ether_arp *arp;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct ether_arp)) {
    fprintf(stderr, "lest(%d) < sizeof(struct iphdr)\n", lest);
    return -1;
  }
  arp = (struct ether_arp *)ptr;
  ptr += sizeof(struct ether_arp);
  lest -= sizeof(struct ether_arp);

  printArp(arp, stdout);
  return 0;
}

int analyzeIcmp(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct icmp *icmp;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct icmp)) {
    fprintf(stderr, "lest(%d) < sizeof(struct icmp)\n", lest);
    return -1;
  }
  icmp = (struct icmp *)ptr;
  ptr += sizeof(struct icmp);
  lest -= sizeof(struct icmp);

  printIcmp(icmp, stdout);
  return 0;
}

int analyzeIcmp6(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct icmp6_hdr *icmp6;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct icmp6_hdr)) {
    fprintf(stderr, "lest(%d) < sizeof(struct icmp6_hdr)\n", lest);
    return -1;
  }
  icmp6 = (struct icmp6_hdr *)ptr;
  ptr += sizeof(struct icmp6_hdr);
  lest -= sizeof(struct icmp6_hdr);

  printIcmp6(icmp6, stdout);
  return 0;
}

int analyzeTcp(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct tcphdr *tcphdr;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct tcphdr)) {
    fprintf(stderr, "lest(%d) < sizeof(struct tcphdr)\n", lest);
    return -1;
  }
  tcphdr = (struct tcphdr *)ptr;
  ptr += sizeof(struct tcphdr);
  lest -= sizeof(struct tcphdr);

  printTcp(tcphdr, stdout);
  return 0;
}

int analyzeUdp(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct udphdr *udphdr;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct udphdr)) {
    fprintf(stderr, "lest(%d) < sizeof(struct udphdr)\n", lest);
    return -1;
  }
  udphdr = (struct udphdr *)ptr;
  ptr += sizeof(struct udphdr);
  lest -= sizeof(struct udphdr);

  printUdp(udphdr, stdout);
  return 0;
}

int analyzeIp(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct iphdr *iphdr;
  unsigned char *option;
  int optionLen, len;
  unsigned short sum;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct iphdr)) {
    fprintf(stderr, "lest(%d) < sizeof(struct iphdr)\n", lest);
    return -1;
  }
  iphdr = (struct iphdr *)ptr;
  ptr += sizeof(struct iphdr);
  lest -= sizeof(struct iphdr);
  optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
  if (optionLen > 0) {
    if (optionLen >= 1500) {
      fprintf(stderr, "Ip optionLen(%d):too big\n", optionLen);
      return -1;
    }
    option = ptr;
    ptr += optionLen;
    lest -= optionLen;
  }

  if (checkIPchecksum(iphdr, option, optionLen) == 0) {
    fprintf(stderr, "bad ip checksum\n");
    return -1;
  }

  printIpHeader(iphdr, option, optionLen, stdout);

  switch (iphdr->protocol) {
  case IPPROTO_ICMP:
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    sum = checksum(ptr, len);
    if (sum != 0 && sum != 0xFFFF) {
      fprintf(stderr, "bad icmp checksum\n");
      return -1;
    }
    analyzeIcmp(ptr, lest);
    break;
  case IPPROTO_TCP:
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    if (checkIPDATAchecksum(iphdr, ptr, len) == 0) {
      fprintf(stderr, "bad tcp checksum\n");
      return -1;
    }
    analyzeTcp(ptr, lest);
    break;
  case IPPROTO_UDP:
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    struct udphdr *udphdr = (struct udphdr *)ptr;
    if (udphdr->check != 0 && checkIPDATAchecksum(iphdr, ptr, len) == 0) {
      fprintf(stderr, "bad ucp checksum\n");
      return -1;
    }
    analyzeUdp(ptr, lest);
    break;
  }
  return 0;
}

int analyzeIpv6(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct ip6_hdr *ip6;
  int len;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct ip6_hdr)) {
    fprintf(stderr, "lest(%d) < sizeof(struct ip6_hdr)\n", lest);
    return -1;
  }
  ip6 = (struct ip6_hdr *)ptr;
  ptr += sizeof(struct ip6_hdr);
  lest -= sizeof(struct ip6_hdr);
  printIp6Header(ip6, stdout);

  switch (ip6->ip6_nxt) {
  case IPPROTO_ICMPV6:
    len = ntohs(ip6->ip6_plen);
    if (checkIP6DATAchecksum(ip6, ptr, len) == 0) {
      fprintf(stderr, "bad icmp6 checksum\n");
      return -1;
    }
    analyzeIcmp6(ptr, lest);
    break;
  case IPPROTO_TCP:
    len = ntohs(ip6->ip6_plen);
    if (checkIP6DATAchecksum(ip6, ptr, len) == 0) {
      fprintf(stderr, "bad tcp6 checksum\n");
      return -1;
    }
    analyzeTcp(ptr, lest);
    break;
  case IPPROTO_UDP:
    len = ntohs(ip6->ip6_plen);
    if (checkIP6DATAchecksum(ip6, ptr, len) == 0) {
      fprintf(stderr, "bad udp6 checksum\n");
      return -1;
    }
    analyzeUdp(ptr, lest);
    break;
  }
  return 0;
}

int analyzePacket(unsigned char *data, int size) {
  unsigned char *ptr;
  int lest;
  struct ether_header *eh;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct ether_header)) {
    fprintf(stderr, "lest(%d) < sizeof(struct ether_header)\n", lest);
    return -1;
  }
  eh = (struct ether_header *)ptr;
  ptr += sizeof(struct ether_header);
  lest -= sizeof(struct ether_header);

  switch (ntohs(eh->ether_type)) {
  case ETHERTYPE_ARP:
    fprintf(stderr, "Packet[%dbytes]\n", size);
    printEtherHeader(eh, stdout);
    analyzeArp(ptr, lest);
    break;
  case ETHERTYPE_IP:
    fprintf(stderr, "Packet[%dbytes]\n", size);
    printEtherHeader(eh, stdout);
    analyzeIp(ptr, lest);
    break;
  case ETHERTYPE_IPV6:
    fprintf(stderr, "Packet[%dbytes]\n", size);
    printEtherHeader(eh, stdout);
    analyzeIpv6(ptr, lest);
    break;
  }

  return 0;
}
