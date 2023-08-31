#include <sys/types.h>

u_int16_t checksum(unsigned char *data, int len);
u_int16_t checksum2(unsigned char *data1, int len1, unsigned char *data2,
                    int len2);
int checkIPchecksum(struct iphdr *iphdr, unsigned char *option, int optionLen);
int checkIPDATAchecksum(struct iphdr *iphdr, unsigned char *data, int len);
int checkIP6DATAchecksum(struct ip6_hdr *ip, unsigned char *data, int len);
