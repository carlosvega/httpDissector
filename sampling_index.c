#include "sampling_index.h"

#define INTERVAL_BLOCK 100
#define INTERVAL_MIN_TIME 120
#define MIN_TIME_BETWEEN_INTERVALS 900

typedef enum { false, true } bool;

long size_of_file(char *filename){
	FILE *f = fopen(filename, "r");
	fseek(f, 0L, SEEK_END);
	long sz = ftell(f);
	fclose(f);
	return sz;
}

interval* read_index(char *index_filename, char *original_file, unsigned long *inter_ctr){

	fprintf(stderr, "%s %s\n", index_filename, original_file);

	long original_file_size = size_of_file(original_file);

	unsigned long ctr = 0, interval_ctr = 0, byte_ctr = 0, avg_interval_size = 0, avg_packets_in_interval = 0;
	unsigned long intervals_max_size = INTERVAL_BLOCK;
	interval *intervals = calloc(INTERVAL_BLOCK, sizeof(interval));
	unsigned long last_interval_ts = 0;
	

	FILE *index_file = fopen(index_filename, "r");
	if( index_file == NULL ){
      perror("Error while opening the index file.\n");
      exit(EXIT_FAILURE);
	}

	//FOR EACH LINE IN FILE
	unsigned long long pkt, byte, ts, pps; //PPS = packets per second
	double average_pps;
	short one = 0;

	bool in_interval = false;

	while(fscanf(index_file, "%llu %hd %llu %llu %llu %lf", &pkt, &one, &byte, &ts, &pps, &average_pps) >= 6){

		if(!in_interval){
			//NEW INTERVAL
			if(pps >= average_pps && (ts - last_interval_ts) > MIN_TIME_BETWEEN_INTERVALS){
				in_interval = true;

				intervals[interval_ctr].start_packet = pkt;
				intervals[interval_ctr].start_byte   = byte;
				intervals[interval_ctr].start_ts	 = ts;

			}
		}else{ //IN INTERVAL
			//END OF INTERVAL
			if(pps < average_pps && ((ts - intervals[interval_ctr].start_ts) > INTERVAL_MIN_TIME)){
				intervals[interval_ctr].end_packet = pkt;
				intervals[interval_ctr].end_byte   = byte;
				intervals[interval_ctr].end_ts	   = ts;

				//fprintf(stdout, "FROM %llu TO %llu BYTES: %llu\n", intervals[interval_ctr].start_ts, intervals[interval_ctr].end_ts, intervals[interval_ctr].end_byte - intervals[interval_ctr].start_byte);
				byte_ctr += (intervals[interval_ctr].end_byte - intervals[interval_ctr].start_byte);
				avg_interval_size += (intervals[interval_ctr].end_ts - intervals[interval_ctr].start_ts);
				avg_packets_in_interval += (intervals[interval_ctr].end_packet - intervals[interval_ctr].start_packet);
				interval_ctr++;
				in_interval = false;
				last_interval_ts = ts;

				if(interval_ctr == intervals_max_size){
					intervals_max_size = intervals_max_size + intervals_max_size*0.5;
					intervals = realloc(intervals, intervals_max_size*sizeof(interval));
				}
			}
		}

		ctr++;
	}

	fprintf(stderr, "INTERVALS:                   %lu\n", interval_ctr);
	fprintf(stderr, "AVERAGE SIZE OF INTERVAL:    %.2lf secs\n", avg_interval_size/((double) interval_ctr));
	fprintf(stderr, "AVERAGE PACKETS IN INTERVAL: %.2lf pkts\n", avg_packets_in_interval/((double) interval_ctr));
	fprintf(stderr, "%% A PROCESAR DEL FICHERO:    %lf%%\n", byte_ctr/((double) original_file_size));

	*inter_ctr = interval_ctr;
	fclose(index_file);
	return intervals;
 
}

// int main(){
	
// 	interval *intervals = read_index("indice.txt", "/Users/carlosvega/samples/merge_http.pcap");
// 	free(intervals);

// 	return 0;
// }




