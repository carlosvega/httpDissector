#ifndef _args_parse_h
#define _args_parse_h

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define ARGS_PARSE_ERRBUF 64

typedef enum {OR=0, AND, OVERWRITE} filter_mode;

struct args_parse{
	char errbuf[ARGS_PARSE_ERRBUF];
	short skip;
	short raw;
	short err;
	short collector;
	short binary;
	short rrd;
	short verbose;
	short twolines;
	short files;
	short log;
	short charts;
	char *output;
	char *index;
	char *gcoutput;
	char *input;
	char *discards;
	char *filter;
	int hpcap;
	int hpcap_ifindex;
	int hpcap_qindex;
	short filter_mode;
	char *interface;
	char *url;
	char *host;
	short version;
	short noRtx;
	short debug;
	short sorted;
	short agent;
};

void how_to_use(char *name);
struct args_parse parse_args(int argc, char **argv);

#endif