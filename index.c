#include "index.h"
extern FILE *index_file;
extern struct timespec last_packet;
extern struct timeval start;
static struct timespec timespec_start;

#define INTERVAL 5*60

struct timespec last_index_entry;
int first = 1;

void write_to_index_with_ts(long int position, struct timespec ts){

	if(first == 1){
		fprintf(index_file, "%ld %ld\n", (long) ts.tv_sec, position);
		last_index_entry = ts;
		first = 0;
	}

	timespec_start = timeval_to_timespec(start);

	struct timespec elapsed = tsSubtract (ts, last_index_entry);

	if(elapsed.tv_sec >= INTERVAL){
		fprintf(index_file, "%ld %ld\n", (long) ts.tv_sec, position);
		last_index_entry = ts;
	}
}

void write_to_index(long int position){
	write_to_index_with_ts(position, last_packet);
}