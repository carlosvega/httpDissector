#include "httpDissector.h"
char version[32] = "Version 3b";

struct args_parse check_args(int argc, char *argv[]){
	struct args_parse options = parse_args(argc, argv);
	if(options.err == -3){
		how_to_use(argv[0]);
		FREE(options.filter);
		options.filter = NULL;
		exit(0);
	}
	if(options.err < 0){
		fprintf(stderr, "\nError: %s\n", options.errbuf);
		how_to_use(argv[0]);
		FREE(options.filter);
		options.filter = NULL;
		exit(-1);
	}

	if(options.version){
		fprintf(stderr, "%s\n", version);
		exit(0);
	}

	if(options.debug != 0){
		fprintf(stderr, "DEBUG/ Activated\n");
		fprintf(stderr, "DEBUG/ RAW: %s\n", options.raw ? "true" : "false");
		fprintf(stderr, "DEBUG/ Files: %s\n", options.files ? "true" : "false");
		fprintf(stderr, "DEBUG/ Log: %s\n", options.log ? "true" : "false");
		fprintf(stderr, "DEBUG/ Input File: %s\n", options.input);
		fprintf(stderr, "DEBUG/ Output File: %s\n", options.output ? options.output : "STDOUT");
		fprintf(stderr, "DEBUG/ Version: %s\n", version);
		fprintf(stderr, "DEBUG/ Verbose: %s\n", options.verbose ? "true" : "false");
		fprintf(stderr, "DEBUG/ Interface: %s\n", options.interface ? options.interface : "false");
		fprintf(stderr, "DEBUG/ TwoLines: %s\n", options.twolines ? "true" : "false");
		fprintf(stderr, "DEBUG/ RRD: %s\n", options.rrd ? "true" : "false");
		fprintf(stderr, "DEBUG/ Debug: %d\n", options.debug);
		fprintf(stderr, "DEBUG/ Index: %s\n", options.index);
		fprintf(stderr, "DEBUG/ Filter: %s\n", options.filter == NULL ? "NO FILTER" : options.filter );
		fprintf(stderr, "\n");
	}

	if(options.raw == 1){
		strcpy(options.format, NDLTFORMAT_DRIV_STR);
	}else{
		strcpy(options.format, NDLTFORMAT_PCAP_STR);
	}	

	if(options.output != NULL){
		options.output_file = fopen(options.output, "w");	
		
		if(options.output_file == NULL){
			fprintf(stderr, "ERROR TRYING TO OPEN THE OUTPUT FILE\n");
			FREE(options.filter);
			exit(-2);
		}
	}else{
		options.output_file = stdout;
	}

	if(options.gcoutput != NULL){
		options.gcoutput_file = fopen(options.gcoutput, "w");
		if(options.gcoutput_file == NULL){
			fprintf(stderr, "ERROR TRYING TO OPEN THE GC-OUTPUT FILE\n");
			FREE(options.filter);
			exit(-8);
		}
	}

	if(options.files){
		options.files_path = parse_list_of_files(options.input, &nFiles);
		if(options.files_path == NULL){
			fprintf(stderr, "Failure parsing list of files\n");
			exit(-1);
		}
	}
	return options;
}

int main(int argc, char *argv[]){
	fprintf(stderr, "SIZE OF HTTP EVENT: %lu\n", sizeof(http_event));
	fprintf(stderr, "SIZE OF HTTP EVENT POINTER: %lu\n", sizeof(http_event*));
	fprintf(stderr, "SIZE OF HTTP CELL: %lu\n", sizeof(collision_list));
	fprintf(stderr, "SIZE OF HTTP CELL POINTER: %lu\n", sizeof(collision_list*));
	fprintf(stderr, "MAIN!\n");
	struct args_parse options = check_args(argc, argv);

	//ALLOC STUFF
	//ALLOC POOL
	fprintf(stderr, "ALLOC POOL!\n");
	alloc_http_event_pool();
	//ALLOC TABLE
	fprintf(stderr, "ALLOC TABLE!\n");
	alloc_event_table();
	fprintf(stderr, "END ALLOCS!\n");

	process_info *processing = (process_info*) calloc(1, sizeof(process_info)); //STORES INFO OF THE CURRENT PROCESS
	pthread_mutex_init(&processing->mutex, NULL);
	int ret = begin_process(&options, processing);
	//TODO CHECK RET

	//CLOSE FILES
	if(options.output != NULL){
		fclose(options.output_file);
	}

	if(options.gcoutput != NULL){
		fclose(options.gcoutput_file);
	}

	fprintf(stderr, "FREE FILES PATH\n");
	if(options.files_path != NULL){
		int i=0;
		for(i=0; i<nFiles; i++){
			FREE(options.files_path[i]);
		}
		FREE(options.files_path);
		options.files_path = NULL;
	}

	//FREE RESOURCES
	//FREE POOL
	fprintf(stderr, "FREEING EVENT POOL\n");
	// free_http_event_pool();
	//FREE TABLE
	fprintf(stderr, "FREEING EVENT TABLE\n");
	// free_event_table();
	//FREE PROCESS INFO
	fprintf(stderr, "FREEING PROCESSING\n");
	FREE(processing);
}






















