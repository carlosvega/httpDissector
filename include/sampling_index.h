#ifndef _sampling_index
#define _sampling_index
#include <stdio.h>
#include <stdlib.h>

typedef struct {
	unsigned long long start_packet;
	unsigned long long start_ts;
	unsigned long long start_byte;

	unsigned long long end_packet;
	unsigned long long end_ts;
	unsigned long long end_byte;
} interval;

interval *read_index(char *index_filename, char *original_file, unsigned long *inter_ctr);

#endif