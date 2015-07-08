#ifndef _hpcapUtils
#define _hpcapUtils

#include <sys/types.h>
#include <pcap.h>

typedef void (*hpcap_handler)(u_int8_t *payload, struct pcap_pkthdr *header, void *arg);

int hpcap_packet_online_loop(int cpu, int ifindex, int qindex, hpcap_handler callback, void *arg);

#endif