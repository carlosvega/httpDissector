#include "httpDissector.h"
char version[32] = "Version 3.1b";

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
	struct args_parse options = check_args(argc, argv);

	fprintf(stderr, "Size of the HTTP event: %lu\n", sizeof(http_event));
	fprintf(stderr, "Size of HTTP Cell: %lu\n", sizeof(collision_list));

	//ALLOC STUFF
	fprintf(stderr, "Collision list pool allocation...\n");
	alloc_collision_list_pool();
	
	fprintf(stderr, "HTTP event pool allocation...\n");
	alloc_http_event_pool();
	
	fprintf(stderr, "Hash table allocation...\n");
	alloc_event_table();

	fprintf(stderr, "Memory Allocation finished.\n");

	process_info *processing = (process_info*) calloc(1, sizeof(process_info)); //STORES INFO OF THE CURRENT PROCESS
	pthread_mutex_init(&processing->mutex, NULL);
	begin_process(&options, processing);
	//TODO CHECK RET

	//CLOSE FILES
	if(options.output != NULL){
		fclose(options.output_file);
	}

	if(options.gcoutput != NULL){
		fclose(options.gcoutput_file);
	}

	fprintf(stderr, "Freeing resources...\n");
	if(options.files_path != NULL){
		int i=0;
		for(i=0; i<nFiles; i++){
			FREE(options.files_path[i]);
		}
		FREE(options.files_path);
		options.files_path = NULL;
	}

	//FREE RESOURCES
	// free_http_event_pool();
	// free_event_table();;
	FREE(processing);

	return 0;
}






















