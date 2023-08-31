#include "analyze.h"
#include <arpa/inet.h>
#include <bits/types/struct_timeval.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// pcap.h on Linux did not perform correctly.
// so, this is my own structure following pcap file format.
typedef struct pcap_pkthdr_s {
  u_int32_t ts_sec;   /* timestamp seconds */
  u_int32_t ts_usec;  /* timestamp microseconds */
  u_int32_t incl_len; /* number of octets of packet saved in file */
  u_int32_t orig_len; /* actual length of packet */
} pcap_pkthdr_t;

// device: network interface name
// promiscFlag: flag whether to be in promiscuous mode or not
// ipOnly: flag whether only IP packets are targeted or not
int initRawSocket(char *device, int promiscFlag, int ipOnly) {
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int soc;

  if (ipOnly) {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
      perror("socket");
      return (-1);
    }
  } else {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
      perror("socket");
      return (-1);
    }
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
  if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
    perror("ioctl");
    close(soc);
    return (-1);
  }
  sa.sll_family = PF_PACKET;
  if (ipOnly) {
    sa.sll_protocol = htons(ETH_P_IP);
  } else {
    sa.sll_protocol = htons(ETH_P_ALL);
  }
  sa.sll_ifindex = ifreq.ifr_ifindex;
  if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(soc);
    return (-1);
  }

  if (promiscFlag) {
    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return (-1);
    }
    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
    if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return (-1);
    }
  }

  return soc;
}

struct pcap_file_header initPcapGlobalHeader() {
  struct pcap_file_header ghdr = {
      .magic = 0xA1B2C3D4, // Set Timestamp (sec, μsec)
      .version_major = PCAP_VERSION_MAJOR,
      .version_minor = PCAP_VERSION_MINOR,
      .thiszone = 0,
      .sigfigs = 0,
      .snaplen = 65535,
      // とりあえず1(Ethernet)のみ対応
      .linktype = 1,
  };
  return ghdr;
}

pcap_pkthdr_t initPcapPacketHeader(uint32_t caplen, uint32_t len) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  pcap_pkthdr_t phdr = {
      .ts_sec = tv.tv_sec,
      .ts_usec = tv.tv_usec,
      .incl_len = caplen,
      .orig_len = len,
  };
  return phdr;
}

void createPcapFile(unsigned char *buf, int size, FILE *fp) {
  pcap_pkthdr_t phdr = initPcapPacketHeader(size, size);
  if (fwrite(&phdr, sizeof(pcap_pkthdr_t), 1, fp) < 1) {
    fprintf(stderr, "failed to fwrite phdr\n");
    return;
  }
  if (fwrite(buf, size, 1, fp) < 1) {
    fprintf(stderr, "failed to fwrite data\n");
    return;
  }
  fflush(fp);
}

int main(int argc, char *argv[], char *envp[]) {
  int soc;
  u_int32_t size;
  unsigned char buf[65535] = {0};

  if (argc <= 1) {
    fprintf(stderr, "pcap [device-name]\n");
    return 1;
  }

  if ((soc = initRawSocket(argv[1], 1, 0)) == -1) {
    fprintf(stderr, "initRawSocket():Error %s\n", argv[1]);
    return -1;
  }

  FILE *fp;
  fp = fopen("test.pcap", "wb");
  if (fp == NULL) {
    fprintf(stderr, "failed to create pcap file\n");
    return 1;
  }
  struct pcap_file_header ghdr = initPcapGlobalHeader();
  /* fwrite(&ghdr, sizeof(struct pcap_file_header), 1, fp); */
  fwrite(&ghdr, sizeof(struct pcap_file_header), 1, fp);
  fflush(fp);

  while (1) {
    if ((size = read(soc, buf, sizeof(buf))) <= 0) {
      perror("read");
    } else {
      /* analyzePacket(buf, size); */
      createPcapFile(buf, size, fp);
    }
  }

  if (fclose(fp) == EOF) {
    fprintf(stderr, "failed to fclose\n");
    return 1;
  }
  close(soc);
  return 0;
}
