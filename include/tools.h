#ifndef _tools
#define _tools

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>
// #include "util.h"
#include "packet_info.h"

typedef enum { false, true } bool;

struct timespec timeval_to_timespec(struct timeval ts);
void increment_total_requests();
unsigned long long get_total_requests();
void print_backtrace(char *err);
struct  timespec  tsSubtract (struct  timespec  t1, struct  timespec  t2);
struct  timespec  tsSubtract2 (struct  timespec  t1, struct  timespec  t2);
struct  timespec  tsAdd (struct  timespec  time1, struct  timespec  time2);
double  tsFloat (struct  timespec  time);
const char *boyermoore_search(const char *haystack, const char *needle);
char *timeval_to_char(struct timespec ts);
char ** parse_list_of_files(char *filename, unsigned int *n_files);
int  tsCompare (struct  timespec  time1, struct  timespec  time2);

#endif