#ifndef _args_parse_h
#define _args_parse_h

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define ARGS_PARSE_ERRBUF 64

struct args_parse{
	char errbuf[ARGS_PARSE_ERRBUF];
	short raw;
	short err;
	short collector;
	short rrd;
	short verbose;
	short twolines;
	short files;
	short log;
	char *output;
	char *gcoutput;
	char *input;
	char *filter;
	char *interface;
	char *url;
	char *host;
	short version;
	short debug;
	short sorted;
};

void how_to_use(char *name);
struct args_parse parse_args(int argc, char **argv);

#endif