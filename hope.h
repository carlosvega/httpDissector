#ifndef _hope
#define _hope

#include <sys/resource.h>
#include <errno.h>

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
#include "util.h"
#include "NDleeTrazas.h"
#include <glib.h>
#include <signal.h>

#define SNAPLEN 65535
#define PROMISC 1
#define to_MS 1000 //specifies the read timeout in milliseconds.

/* ethernet headers are always exactly 14 bytes */

static unsigned long packets = 0;
struct timeval start; 
static unsigned long pcap_size = 0;
static int running = 0;
static FILE *pcapfile = NULL;
static FILE *output = NULL;
NDLTdata_t *ndldata = NULL;
struct args_parse options;

void funcionLiberacion(gpointer data);
void print_foreach (gpointer key, gpointer value, gpointer user_data);
void online_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet);

#endif