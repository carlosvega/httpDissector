#include "httpDissector.h"

extern struct msgbuf sbuf;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t collector;
pthread_t progress;

//REQUEST STATS
unsigned long long get_requests = 0;
unsigned long long post_requests = 0;
unsigned long long head_requests = 0;
unsigned long long put_requests = 0;
unsigned long long trace_requests = 0;
unsigned long long delete_requests = 0;
unsigned long long options_requests = 0;
unsigned long long patch_requests = 0;

node_l *active_session_list = NULL;
uint32_t active_session_list_size = 0;
unsigned long long active_requests = 0;

unsigned long long total_requests = 0;
unsigned long long total_connexions = 0;

unsigned long long total_req_node = 0;
unsigned long long total_out_of_order = 0;

node_l static_node;
node_l *nodel_aux;

collision_list session_table[MAX_FLOWS_TABLE_SIZE] = { {0} };	//2^24

unsigned long long no_cases = 0;
packet_info *pktinfo = NULL;

#define GC_SLEEP_SECS 25

char version[32] = "Version 2.61";
struct args_parse options;

struct timespec last_packet;

struct rusage* memory = NULL;

unsigned long long parse_time = 0;
unsigned long long insert_time = 0;
unsigned long long inserts = 0;
unsigned long long lost = 0;
unsigned long long requests = 0;
unsigned long transacctions = 0;

char format[8] = {0};

char *filter = NULL;
char *global_filename = NULL;

//PARALLEL PROCESSING

char **files_path = NULL;
int last_file = -1;
pid_t father_pid;
short progress_bar = 1;
char *child_filename = NULL;
char new_filename[256] = {0};

FILE *output = NULL;
FILE *gcoutput = NULL;

//HTTP
http_packet http = NULL;

void print_info(long elapsed);
int main_process(char *format, char *filename);
unsigned long remove_old_active_nodes(struct timespec last_packet);

void sigintHandler(int sig){
	signal(SIGINT, SIG_DFL);
	struct timeval end;
	gettimeofday(&end, NULL);

	fprintf(stderr, "\n\nSkipping, wait...\n");
	
	remove_old_active_nodes(last_packet);
	running = 0;
	
	if(options.interface == NULL && progress_bar){
		pthread_join(progress, NULL);
	}
	
	long elapsed = end.tv_sec - start.tv_sec;

	print_info(elapsed);

	if(options.output != NULL){
		fclose(output);
	}

	if(options.gcoutput != NULL){
		fclose(gcoutput);
	}

	if(files_path != NULL){
		int i=0;
		for(i=0; i<nFiles; i++){
			FREE(files_path[i]);
		}
		FREE(files_path);
		files_path = NULL;
	}

	// FREE(filter);
	// FREE(pktinfo);
	// http_free_packet(&http);
	if(options.interface == NULL){
		freeConnectionPool();
		freeNodelPool();
		freeRequestPool();	
	}
	
	// err_mqueue_close();
	
	exit(0);
}


unsigned long remove_old_active_nodes(struct timespec last_packet){

	unsigned long removed = 0;
	uint32_t processed = active_session_list_size;

	ERR_MSG("remove_old_active_nodes\n");

	if(active_session_list_size == 0){
		return removed;
	}

	node_l *last = list_get_last_node(&active_session_list);

	struct timespec diff;
	while(processed>0){
		if(last == NULL){
			return removed;
		}

		node_l *n = last;
		last = last->prev;

		connection *conn = (connection*) n->data;
		conn->active_node = n;
		diff = tsSubtract(last_packet, conn->last_ts);
		if(diff.tv_sec > 60){
			cleanUpConnection(conn, gcoutput);
			uint32_t index = getIndexFromConnection(conn);
			node_l *list = session_table[index].list;
			node_l *conexion_node = NULL;
			if(list == NULL){
				// fprintf(stderr, "list == NULL\n");
				removeActiveConnexion(conn);
			}else if((conexion_node = list_search(list, n, compareConnection))==NULL){				
				fprintf(stderr, "conexion_node == NULL %"PRIu32" %s\n", index, session_table[index].list == NULL? "NULL": "!NULL");
				if(session_table[index].list != NULL && session_table[index].list->data != NULL){
					conn->active_node = n;
					conexion_node = session_table[index].list;
					removeConnexion(conn, conexion_node, index);
				}else{
					removeActiveConnexion(conn);	
				}
			}else{
				removeConnexion(conn, conexion_node, index);
			}
			removed++;
		}
		
		processed--;

	}

	return removed;
}

void *recolector_de_basura(){ 

	if (options.verbose){
		ERR_MSG("DEBUG/ COLLECTOR INITIALIZED\n");
	}

	short l=0;
	//60 sleeps of 1 second, just to be able to end the thread properly
	while(l<GC_SLEEP_SECS){ sleep(1); running == 0 ? l=GC_SLEEP_SECS : l++;}
	while(running){
		pthread_mutex_lock(&mutex);
		l=0;
	 	if(options.log){
			syslog (LOG_NOTICE, "Elements in table hash before removing entries: %"PRIu32"\n", active_session_list_size);
		}
        if (options.verbose)
        {
            ERR_MSG("DEBUG/ ==============================\n");
            ERR_MSG("DEBUG/ Elements active in table hash before removing entries: %"PRIu32"\n", active_session_list_size);
        }
	 	unsigned long removed = remove_old_active_nodes(last_packet);
        if (options.verbose)
        {
            ERR_MSG("DEBUG/ Elements active in table hash after removing entries: %"PRIu32" Removed: %ld\n", active_session_list_size, removed);
            ERR_MSG("DEBUG/ ==============================\n\n");
        }
        if(options.log){
			syslog (LOG_NOTICE, "Elements in table hash after removing entries: %"PRIu32" Removed: %ld\n", active_session_list_size, removed);
		}
		pthread_mutex_unlock(&mutex);
	 	while(l<GC_SLEEP_SECS){ sleep(1); running == 0 ? l=GC_SLEEP_SECS : l++;}
	}

	return NULL;
}

void loadBar(unsigned long long x, unsigned long long n, unsigned long long r, int w)
{
 
  struct timeval aux_exec;
  struct timeval elapsed;

  	// Only update r times.
    if ( x % (n/r) != 0 ) return;
 
    // Calculuate the ratio of complete-to-incomplete.
    float ratio = x/(float)n;
    int   c     = ratio * w;
 
    // Show the percentage complete. 
    fprintf(stderr, "%3.0d%% [", ((int)(ratio*100)));

    int i=0;

    // Show the load bar.
    for (i=0; i<c; i++)
       fprintf(stderr, "=");
 
    for (i=c; i<w; i++)
       fprintf(stderr, " ");

   	fprintf(stderr, "]");

   	gettimeofday(&aux_exec, NULL);  
  	timersub(&aux_exec, &start, &elapsed);
  	
  	if(options.files){
  		fprintf(stderr, " Elapsed Time: (%ld %.2ld:%.2ld:%.2ld)\tRead Speed: %lld MB/s\tFile: (%d/%d)", (elapsed.tv_sec/86400), (elapsed.tv_sec/3600)%60, (elapsed.tv_sec/60)%60, (elapsed.tv_sec)%60, elapsed.tv_sec == 0 ? 0 : x/(elapsed.tv_sec*1024*1024), ndldata->contFiles, nFiles);
  	}else{
		fprintf(stderr, " Elapsed Time: (%ld %.2ld:%.2ld:%.2ld)\tRead Speed: %lld MB/s\t", (elapsed.tv_sec/86400), (elapsed.tv_sec/3600)%60, (elapsed.tv_sec/60)%60, (elapsed.tv_sec)%60, elapsed.tv_sec == 0 ? 0 : x/(elapsed.tv_sec*1024*1024));
	}
	if(options.log){
		syslog (LOG_NOTICE, "SPEED: %ld secs @ %lld MB/s PROGRESS: %3.0d%%", elapsed.tv_sec, elapsed.tv_sec == 0 ? 0 : x/(elapsed.tv_sec*1024*1024), ((int)(ratio*100)));
		syslog(LOG_NOTICE, "G.REQ: %lld (%lld) ACTIVE_REQ: %lld ACTIVE_CONNEXIONS: %"PRIu32" (%lld) G.RESP: %"PRIu32"", getGottenRequests(), total_requests, active_requests, active_session_list_size, total_connexions, getGottenResponses());
    	getrusage(RUSAGE_SELF, memory);
		if(errno == EFAULT){
		    syslog (LOG_NOTICE, "MEM Error: EFAULT\n");
		}else if(errno == EINVAL){
		    syslog (LOG_NOTICE, "MEM Error: EINVAL\n");
		}else{
			syslog (LOG_NOTICE, "MEM %ld\t%ld", elapsed.tv_sec, memory->ru_maxrss);
		}
	}

    // ANSI Control codes to go back to the
    // previous line and clear it.
    fprintf(stderr, "\n\033[F");
    fprintf(stderr, "\r");
    //fflush(stderr);
}

void *barra_de_progreso(){
  
  static long sleeptime = 2000000;

  if(options.log){
		sleeptime = 5000000;
  }

  	while(running){
  		loadBar(ndldata->bytesTotalesLeidos, ndldata->bytesTotalesFicheros, ndldata->bytesTotalesFicheros, 40);
  		usleep(sleeptime);
  	}
	
	return NULL;
}

int parse_packet(const u_char *packet, const struct NDLTpkthdr *pkthdr, packet_info *pktinfo){
	
	ERR_MSG("DEBUG/ begining parse_packet().\n");
	
	memset(pktinfo->url, 0, URL_SIZE);
	pktinfo->ethernet = (struct sniff_ethernet*)(packet);
	pktinfo->ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	pktinfo->size_ip = IP_HL(pktinfo->ip)*4;

	if (pktinfo->size_ip < 20) {
		
		ERR_MSG("DEBUG/ finish parse_packet(). pktinfo->size_ip < 20\n");
		
		return 1;
	}

	if(pkthdr->caplen < (SIZE_ETHERNET + pktinfo->size_ip + 20)){
		
		ERR_MSG("DEBUG/ finish parse_packet(). pkthdr->caplen < (SIZE_ETHERNET + pktinfo->size_ip + 20)\n");
		
		return 1;
	}

	pktinfo->tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + pktinfo->size_ip);
	pktinfo->size_tcp = TH_OFF(pktinfo->tcp)*4;

	pktinfo->port_src = ntohs(pktinfo->tcp->th_sport);       /* source port */
	pktinfo->port_dst = ntohs(pktinfo->tcp->th_dport);       /* destination port */
      
    if (pktinfo->size_tcp < 20) {
    	
		ERR_MSG("DEBUG/ finish parse_packet(). pktinfo->size_tcp < 20\n");
		
	    return 1;
    }

    pktinfo->payload = (u_char *)(packet + SIZE_ETHERNET + pktinfo->size_ip + pktinfo->size_tcp);
    pktinfo->size_payload = pkthdr->len - SIZE_ETHERNET - pktinfo->size_ip - pktinfo->size_tcp;
    pktinfo->ts = pkthdr->ts;
	inet_ntop(AF_INET, &(pktinfo->ip->ip_src), pktinfo->ip_addr_src, 16);
    inet_ntop(AF_INET, &(pktinfo->ip->ip_dst), pktinfo->ip_addr_dst, 16);

  	ERR_MSG("DEBUG/ calling http_parse_packet().\n");
	
  	if(http_parse_packet((char*) pktinfo->payload, (int) pktinfo->size_payload, &http, pktinfo->ip_addr_src, pktinfo->ip_addr_dst) == -1){
 		http_clean_up(&http);
 		
		ERR_MSG("DEBUG/ finish parse_packet(). http_parse_packet returned -1\n");
		
 		return 1;
 	}

    if(pktinfo->size_payload <= 0){
    	pktinfo->request = -1;
    	http_clean_up(&http);
    	
		ERR_MSG("DEBUG/ finish parse_packet(). pktinfo->size_payload <= 0\n");
		
    	return 1;
    }

    pktinfo->op = http_get_op(http);
	if(pktinfo->op == RESPONSE){
		pktinfo->request = 0;
		pktinfo->responseCode = http_get_response_code(http);
		strncpy(pktinfo->response_msg, http_get_response_msg(http), RESP_MSG_SIZE);
		pktinfo->response_msg[RESP_MSG_SIZE - 1] = 0;
	}else if(http_is_request(pktinfo->op)){
		char * host = http_get_host(http);
		char * uri = http_get_uri(http);
		
		strcpy(pktinfo->host, host);
		strcpy(pktinfo->url, uri);
		

		if(options.url != NULL){
			if(boyermoore_search(pktinfo->url, options.url) == NULL){
				http_clean_up(&http);
				
				ERR_MSG("DEBUG/ finish parse_packet(). boyermoore_search url returned NULL\n");
				
				return 1;
			}
		}

		if(options.host != NULL){
			if(boyermoore_search(pktinfo->host, options.host) == NULL){
				http_clean_up(&http);
				
				ERR_MSG("DEBUG/ finish parse_packet(). boyermoore_search host returned NULL\n");
				
				return 1;
			}
		}

		pktinfo->request = 1;
	}else{
		pktinfo->request = -1;
	}

	
	ERR_MSG("DEBUG/ calling http_clean_up().\n");

	http_clean_up(&http);

	ERR_MSG("DEBUG/ finish parse_packet().\n");

	return 0;
}

void online_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){

	struct NDLTpkthdr pkthdr2;
	pkthdr2.caplen = pkthdr->caplen;
	pkthdr2.len = pkthdr->len;
	pkthdr2.ts.tv_sec = pkthdr->ts.tv_sec;
	pkthdr2.ts.tv_nsec = pkthdr->ts.tv_usec * 1000;

	callback(useless, &pkthdr2, packet);

	return;

}

void callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet)
{
	pthread_mutex_lock(&mutex);
	
	ERR_MSG("-------------\nDEBUG/ begining callback\n");

	memset(pktinfo, 0, sizeof(packet_info));

	last_packet = pkthdr->ts;
	packets++;

  	struct timeval t, t2;  
  	gettimeofday(&t, NULL);
 
	ERR_MSG("DEBUG/ calling parse_packet().\n");
  	int ret = parse_packet(packet, pkthdr, pktinfo);

  	gettimeofday(&t2, NULL);
  	parse_time += ((t2.tv_usec - t.tv_usec)  + ((t2.tv_sec - t.tv_sec) * 1000000.0f));

	if(ret){
		
		ERR_MSG("DEBUG/ finish callback. Invalid packet.\n");
		
		pthread_mutex_unlock(&mutex);
		return;
	}

	if(pktinfo->request == -1){ //NI GET NI RESPONSE
		
		ERR_MSG("DEBUG/ finish callback. Invalid packet II.\n");
		
		pthread_mutex_unlock(&mutex);
		return;
	}
  
	struct timeval t3, t4;  
	gettimeofday(&t3, NULL);
 
	if(pktinfo->request == 1){ //GET o POST

		
		ERR_MSG("DEBUG/ calling insert_get_hashtable.\n");

		if(insertPacket(pktinfo) != 0){
			
			ERR_MSG("DEBUG/ error inserting GET\n");
			
			inserts--;
		}

	}else if(pktinfo->request == 0){ //RESPONSE

		
		ERR_MSG("DEBUG/ calling insert_resp_hashtable.\n");
		
		if(insertPacket(pktinfo) != 0){
			
			ERR_MSG("DEBUG/ error inserting RESP\n");
			
			inserts--;
		}
	}
	 
    gettimeofday(&t4, NULL);
    insert_time += ((t4.tv_usec - t3.tv_usec)  + ((t4.tv_sec - t3.tv_sec) * 1000000.0f));
    inserts++;

	ERR_MSG("DEBUG/ finish callback\n");
	
    pthread_mutex_unlock(&mutex);
}

int main(int argc, char *argv[]){

	fprintf(stderr, "httpDissector %s\n", version);
	//GET 
	//POST
	//HEAD
	//PUT
	//DELETE
	//PATCH
	//TRACE
	//OPTIONS
	//HTTP
	filter = strdup("tcp and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420 \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x5445) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4820) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x54524143 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4520) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x4f4e5320) \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450)");

	options = parse_args(argc, argv);
	if(options.err == -3){
		how_to_use(argv[0]);
		FREE(filter);
		filter = NULL;
		return 0;
	}
	if(options.err < 0){
		fprintf(stderr, "\nError: %s\n", options.errbuf);
		how_to_use(argv[0]);
		FREE(filter);
		filter = NULL;
		return -1;
	}

	if(options.version){
		fprintf(stderr, "%s\n", version);
		return 0;
	}

	if(options.raw == 1){
		strcpy(format, NDLTFORMAT_DRIV_STR);
	}else{
		strcpy(format, NDLTFORMAT_PCAP_STR);
	}

	if(options.filter != NULL){
		filter = (char *) realloc(filter, (strlen(filter) + strlen(options.filter) + 6)*sizeof(char));
		strcat(filter, " and ");
		strcat(filter, options.filter);
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
		fprintf(stderr, "DEBUG/ Filter: %s\n", filter);
		fprintf(stderr, "\n");
	}

	if(options.output != NULL){
		output = fopen(options.output, "w");
		if(output == NULL){
			fprintf(stderr, "ERROR TRYING TO OPEN THE OUTPUT FILE\n");
			FREE(filter);
			return -2;
		}
	}else{
		output = stdout;
	}

	if(options.gcoutput != NULL){
		gcoutput = fopen(options.gcoutput, "w");
		if(output == NULL){
			fprintf(stderr, "ERROR TRYING TO OPEN THE GC-OUTPUT FILE\n");
			FREE(filter);
			return -8;
		}
	}

	if(options.files){
		files_path = parse_list_of_files(options.input, &nFiles);
		if(files_path == NULL){
			fprintf(stderr, "Failure parsing list of files\n");
			return -1;
		}
	}

	//NEW
	allocConnectionPool();
	allocRequestPool();
	// allocResponsePool();
	allocNodelPool();
	//HTTP
	http_alloc(&http);
	//SORTED PRINT LIST
	if(options.sorted){
		initPrintElementList();
	}

	//PACKET_INFO
	pktinfo = (packet_info *) calloc(sizeof(packet_info), 1);
	
	main_process(format, options.input);
	

	if(options.sorted){
		freePrintElementList();
	}

	if(options.output != NULL){
		fclose(output);
	}

	if(options.gcoutput != NULL){
		fclose(gcoutput);
	}

	if(files_path != NULL){
		int i=0;
		for(i=0; i<nFiles; i++){
			FREE(files_path[i]);
		}
		FREE(files_path);
		files_path = NULL;
	}

	freeNodelPool();
	freeConnectionPool();
	freeRequestPool();

	return 0;
}


int main_process(char *format, char *filename){

	global_filename = filename;
	struct bpf_program fp;

	if(options.log){
		
		if(options.interface != NULL){
			options.log = 0;
		}else{
			setlogmask (LOG_UPTO (LOG_DEBUG));
     		openlog ("httpDissector", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	    	syslog (LOG_NOTICE, "Log started by process: %d", getpid());
	    	syslog (LOG_NOTICE, "Reading file: %s", filename);
	    	syslog (LOG_NOTICE, "SPEED secs\tspeed");
	    	syslog (LOG_NOTICE, "MEM secs\tmemory");
	    	memory = malloc(sizeof(struct rusage));
    	}
	}

	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *handle = NULL;

	if(options.interface == NULL){
		// pcapfile = fopen(filename, "r");
		// if(pcapfile == NULL){
		// 	fprintf(stderr, "ERROR TRYING TO OPEN THE INPUT FILE |%s|\n", filename);
		// 	if(options.log){
		// 		closelog ();
		// 	}
		// 	return -2;
		// }

		// struct timeval t, t2;  
		// gettimeofday(&t, NULL);
		// fseek(pcapfile, 0L, SEEK_END);
		// gettimeofday(&t2, NULL);
		// pcap_size = ftell(pcapfile);
		// rewind(pcapfile); 
		// fclose(pcapfile);

		// long microsegundos = ((t2.tv_usec - t.tv_usec)  + ((t2.tv_sec - t.tv_sec) * 1000000.0f));
	 //  	fprintf(stderr, "SIZE: %ld, Time: (%ld)\n", pcap_size, microsegundos);


		
		ERR_MSG("DEBUG/ Before calling NDLTabrirTraza()\n");

	  	if(options.files){
			ndldata = NDLTabrirTraza(filename, format, filter, 1, errbuf);
		}else{
			ndldata = NDLTabrirTraza(filename, format, filter, 0, errbuf);
		}


		ERR_MSG("DEBUG/ After calling NDLTabrirTraza()\n");
		
		if(ndldata == NULL){
			fprintf(stderr, "NULL WHILE OPENING NDL FILE: %s\n", errbuf);
			fprintf(stderr, "File: %s\tRAW flag = %s\n", options.input, options.raw == 0? "false" : "true");
			return -1;
		}


	}else{

		ERR_MSG("DEBUG/ calling pcap_open_live()\n");
		
		handle = pcap_open_live(options.interface, SNAPLEN, PROMISC, to_MS, errbuf);
		if(handle == NULL){
			fprintf(stderr, "Couldn't open device %s: %s\n", options.interface, errbuf);
		 	return -2;
		}

		ERR_MSG("DEBUG/ calling pcap_compile()\n");

		if(pcap_compile(handle, &fp, filter, 1, 0) == -1){
			fprintf(stderr, "Couldn't parse filter, %s\n|%s|", pcap_geterr(handle), filter);
			return -3;
		}

		ERR_MSG("DEBUG/ calling pcap_setfilter()\n");

		if(pcap_setfilter(handle, &fp) == -1){
			fprintf(stderr, "Couldn't install filter, %s\n", pcap_geterr(handle));
			return -4;
		}
	}

	

	ERR_MSG("DEBUG/ Creating hash table\n");

   	//creamos los hilos

	ERR_MSG("DEBUG/ Creating collector thread\n");

	//RECOLECTOR
	if(options.collector){
		pthread_create(&collector, NULL, recolector_de_basura, NULL);
	}
	
	gettimeofday(&start, NULL);
	running = 1;

	ERR_MSG("DEBUG/ Creating progress_bar thread\n");

	//BARRA DE PROGRESO
	if(options.interface == NULL && progress_bar){
		pthread_create(&progress, NULL, barra_de_progreso, NULL);
	}

	signal(SIGINT, sigintHandler);

	struct timeval end;

	ERR_MSG("DEBUG/ before loop\n");
	ERR_MSG("DEBUG/ ===============\n");

	if(options.interface == NULL){
		if(NDLTloop(ndldata, callback, NULL) != 1){
			sigintHandler(1);
		}
	}else{
		pcap_loop(handle, -1, online_callback, NULL);
	}
	gettimeofday(&end, NULL);
	remove_old_active_nodes(last_packet);

	ERR_MSG("DEBUG/ After loop\n");
	ERR_MSG("DEBUG/ ===============\n");

	running = 0;

	ERR_MSG("DEBUG/ closing collector\n");

	if(options.collector){
		pthread_join(collector, NULL);
  	}

  	ERR_MSG("DEBUG/ calling remove_old_active_nodes\n");

	ERR_MSG("DEBUG/ closing progress_bar\n");

  	if(options.interface == NULL && progress_bar){
  		pthread_join(progress, NULL);
  		loadBar(ndldata->bytesTotalesLeidos, ndldata->bytesTotalesLeidos, ndldata->bytesTotalesLeidos, 40);
  		NDLTclose(ndldata);
  	}

	long elapsed = end.tv_sec - start.tv_sec;
	print_info(elapsed);

	return 0;
}

void print_info(long elapsed){
	
	fprintf(stderr, "EY %d - %d\n", lost, requests);
	fprintf(stderr, "\n\nFile: %s \nTotal packets: %ld\nTotal inserts: %lld\nResponse lost ratio (Requests without response): %Lf%%\n", global_filename, packets, inserts, requests == 0 ? 0 : (((long double)lost) / requests)*100);
	
	if(elapsed != 0){
		fprintf(stderr, "Speed: %Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		if(options.log){
			syslog (LOG_NOTICE, "%Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		}
	}

	fprintf(stderr, "RESPONSES OUT OF ORDER: %lld\n", total_out_of_order);
	fprintf(stderr, "RESPONSES WITHOUT REQUEST: %lld\n", lost);

	fprintf(stderr, "\nREQUEST STATS\n");
	fprintf(stderr, "GET: %lld\n", get_requests);
	fprintf(stderr, "POST: %lld\n", post_requests);
	fprintf(stderr, "HEAD: %lld\n", head_requests);
	fprintf(stderr, "PATCH: %lld\n", patch_requests);
	fprintf(stderr, "PUT: %lld\n", put_requests);
	fprintf(stderr, "DELETE: %lld\n", delete_requests);
	fprintf(stderr, "OPTIONS: %lld\n", options_requests);
	fprintf(stderr, "TRACE: %lld\n", trace_requests);

	fflush(stderr);

	return;
}
