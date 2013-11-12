#ifndef _hope
#define _hope

#include <assert.h>
#include "header_list_pool.h"
#include "connection.h"
#include "err_mqueue.h"
#include "list.h"
#include "request.h"
#include "response.h"
#include "packet_info.h"
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

#define SNAPLEN 65535
#define PROMISC 1
#define to_MS 1000 //specifies the read timeout in milliseconds.

/* ethernet headers are always exactly 14 bytes */

typedef struct {
  int n;
  node_l *list;
} colisiones;

static unsigned long packets = 0;
struct timeval start; 
static int running = 0;
NDLTdata_t *ndldata = NULL;
unsigned int nFiles = 0;

// void funcionLiberacion(gpointer data);
// void print_foreach (gpointer key, gpointer value, gpointer user_data);
void online_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet);

#endif
