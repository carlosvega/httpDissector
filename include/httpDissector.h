#ifndef _httpDissector
#define _httpDissector

#include <inttypes.h>
#include <locale.h>
#include <assert.h>
//HPCAP
#ifdef HPCAP_SUPPORT
#include "hpcap_utils.h"
#endif
//
// #include "sampling_index.h"
#include "list.h"
// #include "counters.h"
// #include "connection.h"
// #include "request.h"
// #include "response.h"
// #include "packet_info.h"
#include "tools.h"
#include "NDleeTrazas.h"
#include "http.h"
#include "args_parse.h"

#include <sys/resource.h>
#include <errno.h>

#include <pthread.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <math.h>

#include "process_packet.h"



#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

struct timeval start;
NDLTdata_t *ndldata = NULL;
unsigned int nFiles = 0;

// void funcionLiberacion(gpointer data);
// void print_foreach (gpointer key, gpointer value, gpointer user_data);
void index_callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet);
void online_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet);

#endif
