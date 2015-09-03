#ifdef HPCAP_SUPPORT
#include "hpcap_utils.h"
#include "libmgmon.h"

int hpcap_packet_online_loop(int cpu, int ifindex, int qindex, hpcap_handler callback, void *arg){
	return mgmon_packet_online_loop(cpu, ifindex, qindex, callback, arg);
}
#endif