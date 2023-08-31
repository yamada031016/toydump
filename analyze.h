#include <sys/types.h>

int analyzeArp(unsigned char *data, int size);
int analyzeIcmp(unsigned char *data, int size);
int analyzeIcmp6(unsigned char *data, int size);
int analyzeTcp(unsigned char *data, int size);
int analyzeUdp(unsigned char *data, int size);
int analyzeIp(unsigned char *data, int size);
int analyzeIpv6(unsigned char *data, int size);
int analyzePacket(unsigned char *data, int size);
