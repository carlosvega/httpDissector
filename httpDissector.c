#include "httpDissector.h"

#define GC_SLEEP_SECS 60

extern struct msgbuf sbuf;


//PCAP HANDLER
pcap_t *handle = NULL;

//INDEX
unsigned long interval_ctr = 0;
interval *intervals = NULL;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t collector;
pthread_t progress;

node_l *active_session_list = NULL;
uint32_t active_session_list_size = 0;
uint32_t max_active_session_list_size = 0;

node_l static_node;
node_l *nodel_aux;

// collision_list session_table[MAX_FLOWS_TABLE_SIZE] = { {0} };	//2^24
collision_list *session_table = NULL;
int resized_session_table = 0;

packet_info *pktinfo = NULL;

char version[32] = "Version 2.86b";
struct args_parse options;

struct timespec last_packet;
struct timespec first_packet = {0};

struct rusage* memory = NULL;

char format[8] = {0};

char *filter = NULL;
char *global_filename = NULL;

char **files_path = NULL;
short progress_bar = 1;

FILE *output = NULL;
FILE *gcoutput = NULL;
FILE *index_file = NULL;

//HTTP
http_packet http = NULL;

unsigned long total_packets_in_file = 0;

void reset();
void print_info(long elapsed);
int main_process(char *format, char *filename);
unsigned long remove_old_active_nodes(struct timespec last_packet);

void sigintHandler(int sig){
	signal(SIGINT, SIG_DFL);
	struct timeval end;
	gettimeofday(&end, NULL);

	fprintf(stderr, "\n\nSkipping, wait...\n");
	
	//ºremove_old_active_nodes(last_packet);
	running = 0;
	
	if(options.interface == NULL && progress_bar){
		pthread_join(progress, NULL);
	}
	
	if(options.sorted){
		freePrintElementList();
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
		// freeConnectionPool();
		// freeRequestPool();	
		// freeNodelPool();
	}

	if(options.index!=NULL){
		FREE(intervals);
	}
	
	// err_mqueue_close();
	FREE(session_table);
	
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
				// fprintf(stderr, "conexion_node == NULL %"PRIu32" %s\n", index, session_table[index].list == NULL? "NULL": "!NULL");
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
	 		syslog (LOG_NOTICE, " \n");
			syslog (LOG_NOTICE, "Elements in table hash before removing entries: %"PRIu32"\n", active_session_list_size);
		}
        if (options.verbose)
        {
            ERR_MSG("DEBUG/ ==============================\n");
            ERR_MSG("DEBUG/ Elements active in table hash before removing entries: %"PRIu32"\n", active_session_list_size);
        }
	 	unsigned long removed = remove_old_active_nodes(last_packet);
	 	increment_total_removed_requests(removed);
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

double hash_table_usage(){
	// return resized_session_table ? ((double) active_session_list_size) / ((long double) BIG_MAX_FLOWS_TABLE_SIZE) : ((double) active_session_list_size) / ((long double) MAX_FLOWS_TABLE_SIZE);
	return ((double) active_session_list_size) / ((long double) MAX_FLOWS_TABLE_SIZE);
}

unsigned long hash_table_collisions(){
	uint32_t processed = active_session_list_size;
	unsigned long counter = 0;
	node_l *last = list_get_last_node(&active_session_list);
	
	while (processed>0){
		if(last == NULL){
			return counter;
		}

		node_l *n = last;
		last = last->prev;
		connection *conn = (connection*) n->data;
		uint32_t index = getIndexFromConnection(conn);
		if(session_table[index].n > 1){
			counter += session_table[index].n - 1;
		}

		processed--;
	}

	return counter;
}

double hash_table_collisions_ratio(unsigned long collisions){
	return ((long double) collisions) / ((long double) active_session_list_size + collisions);
}

void loadBar(unsigned long long x, unsigned long long n, unsigned long long r, int w)
{
 
	if(r<=0){
		return;
	}

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
		pthread_mutex_lock(&mutex);
		syslog (LOG_NOTICE, "SPEED: %ld secs @ %lld MB/s PROGRESS: %3.0d%%", elapsed.tv_sec, elapsed.tv_sec == 0 ? 0 : x/(elapsed.tv_sec*1024*1024), ((int)(ratio*100)));
		unsigned long collisions = hash_table_collisions();
		syslog (LOG_NOTICE, "HASH_USAGE: %u %f%% COLLISIONS: %ld COLLISIONS_RATIO: %f%%", active_session_list_size, hash_table_usage()*100, collisions, hash_table_collisions_ratio(collisions)*100);
		syslog (LOG_NOTICE, "POOL USAGE: node_pool: %f%% connections_pool: %f%% requests_pool: %f%%", pool_nodes_used_ratio()*100, pool_connections_used_ratio()*100, pool_requests_used_ratio()*100);
		

		// syslog(LOG_NOTICE, "G.REQ: %lld (%lld) ACTIVE_REQ: %lld ACTIVE_CONNEXIONS: %"PRIu32" (%lld) G.RESP: %"PRIu32"", getGottenRequests(), get_total_requests(), get_active_requests(), active_session_list_size, get_total_connexions(), getGottenResponses());
    	getrusage(RUSAGE_SELF, memory);
		if(errno == EFAULT){
		    syslog (LOG_NOTICE, "MEM Error: EFAULT\n");
		}else if(errno == EINVAL){
		    syslog (LOG_NOTICE, "MEM Error: EINVAL\n");
		}else{
			syslog (LOG_NOTICE, "MEM %ld %ld", elapsed.tv_sec, memory->ru_maxrss);
		}
		pthread_mutex_unlock(&mutex);
	}

    // ANSI Control codes to go back to the
    // previous line and clear it.
    fprintf(stderr, "\033[F");
    fprintf(stderr, "\r");
    //fflush(stderr);
}

void *barra_de_progreso(){
  
  static long sleeptime = 2000000;

  if(options.log){
		sleeptime = 5000000;
  }

  	while(running){
  		if(options.index != NULL){
			loadBar(ftello(NDLTfile(ndldata)), ndldata->bytesTotalesFicheros, ndldata->bytesTotalesFicheros, 40);
  		}else{
  			loadBar(ndldata->bytesTotalesLeidos, ndldata->bytesTotalesFicheros, ndldata->bytesTotalesFicheros, 40);
  		}
  		usleep(sleeptime);
  	}
	
	return NULL;
}

int parse_packet(const u_char *packet, const struct NDLTpkthdr *pkthdr, packet_info *pktinfo){

	// ERR_MSG("DEBUG/ begining parse_packet().\n");
	size_t size_ethernet = SIZE_ETHERNET;
	
	memset(pktinfo->url, 0, URL_SIZE);
	pktinfo->ethernet = (struct sniff_ethernet*)(packet);
	//VLAN
	if (pktinfo->ethernet->ether_type == 0x81){
		size_ethernet += 4;	
	}
	
	pktinfo->ip = (struct sniff_ip*)(packet + size_ethernet);
	pktinfo->size_ip = IP_HL(pktinfo->ip)*4;

	if (pktinfo->size_ip < 20) {
		
		// ERR_MSG("DEBUG/ finish parse_packet(). pktinfo->size_ip < 20\n");
		
		return 1;
	}

	if(pkthdr->caplen < (size_ethernet + pktinfo->size_ip + 20)){
		
		// ERR_MSG("DEBUG/ finish parse_packet(). pkthdr->caplen < (size_ethernet + pktinfo->size_ip + 20)\n");
		
		return 1;
	}

	pktinfo->tcp = (struct sniff_tcp*)(packet + size_ethernet + pktinfo->size_ip);
	pktinfo->size_tcp = TH_OFF(pktinfo->tcp)*4;

	pktinfo->port_src = ntohs(pktinfo->tcp->th_sport);       /* source port */
	pktinfo->port_dst = ntohs(pktinfo->tcp->th_dport);       /* destination port */
      
	pktinfo->tcp->th_seq = ntohl(pktinfo->tcp->th_seq);
    pktinfo->tcp->th_ack = ntohl(pktinfo->tcp->th_ack);
      
    if (pktinfo->size_tcp < 20) {
		// ERR_MSG("DEBUG/ finish parse_packet(). pktinfo->size_tcp < 20\n");
	    return 1;
    }

    pktinfo->payload = (u_char *)(packet + size_ethernet + pktinfo->size_ip + pktinfo->size_tcp);
    pktinfo->size_payload = pkthdr->caplen - size_ethernet - pktinfo->size_ip - pktinfo->size_tcp;
    pktinfo->ts.tv_sec = pkthdr->ts.tv_sec;
    pktinfo->ts.tv_nsec = pkthdr->ts.tv_nsec;
	// inet_ntop(AF_INET, &(pktinfo->ip->ip_src), pktinfo->ip_addr_src, 16);
 //    inet_ntop(AF_INET, &(pktinfo->ip->ip_dst), pktinfo->ip_addr_dst, 16);

  	// ERR_MSG("DEBUG/ calling http_parse_packet().\n");
	
  	if(http_parse_packet(pktinfo->payload, (int) pktinfo->size_payload, &http, pktinfo->ip->ip_src, pktinfo->ip->ip_dst) == -1){
 		http_clean_up(&http);
		// ERR_MSG("DEBUG/ finish parse_packet(). http_parse_packet returned -1\n");
 		return 1;
 	}

    if(pktinfo->size_payload <= 0){
    	pktinfo->request = -1;
    	http_clean_up(&http);
		// ERR_MSG("DEBUG/ finish parse_packet(). pktinfo->size_payload <= 0\n");
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
		char * agent = http_get_agent(http);
		char * uri = http_get_uri(http);
		
		strcpy(pktinfo->agent, agent);
		strcpy(pktinfo->host, host);
		strcpy(pktinfo->url, uri);
		

		if(options.url != NULL){
			if(boyermoore_search(pktinfo->url, options.url) == NULL){
				http_clean_up(&http);
				
				// ERR_MSG("DEBUG/ finish parse_packet(). boyermoore_search url returned NULL\n");
				
				return 1;
			}
		}

		if(options.host != NULL){
			if(boyermoore_search(pktinfo->host, options.host) == NULL){
				http_clean_up(&http);
				
				// ERR_MSG("DEBUG/ finish parse_packet(). boyermoore_search host returned NULL\n");
				
				return 1;
			}
		}

		pktinfo->request = 1;
	}else{
		pktinfo->request = -1;
	}

	
	// ERR_MSG("DEBUG/ calling http_clean_up().\n");

	http_clean_up(&http);

	// ERR_MSG("DEBUG/ finish parse_packet().\n");

	return 0;
}

void index_callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet){

	static unsigned long current_interval = 0;
	static bool in_interval = false;
	static interval i;

	//PROCESSING A NEW INTERVAL
	if(!in_interval && current_interval < interval_ctr){
		i = intervals[current_interval];
		if(NDLTjumpToPacket(ndldata, i.start_packet) == 0){
			//ERR
			fprintf(stderr, "ERROR JUMPING IN FILE %llu\n", i.start_packet);
			exit(1);
		}
		in_interval = true;
	}else{
		if(pkthdr->ts.tv_sec > i.end_ts){
			in_interval = false;
			current_interval++;
		}else{
			callback(useless, pkthdr, packet);
		}
	}

	return;
}

u_int64_t pkts,bytes;
u_int32_t last_sec=0;

void hpcap_callback(u_int8_t *payload, struct pcap_pkthdr *header, void *arg){
	struct NDLTpkthdr pkthdr2;
	pkthdr2.caplen = header->caplen;
	pkthdr2.len = header->len;
	pkthdr2.ts.tv_sec = header->ts.tv_sec;
	pkthdr2.ts.tv_nsec = header->ts.tv_usec * 1000;

	//callback(arg, &pkthdr2, payload);

	fprintf(stderr, "NOT IMPLEMENTED.\n");

	exit(-1);

	return;

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

	//LOCK
	pthread_mutex_lock(&mutex);

	if(first_packet.tv_sec == 0){
		first_packet = pkthdr->ts;
	}

	// packet_counter_for_this_second++;
	last_packet = pkthdr->ts;
	packets++;

	if(packets % options.skip != 0){
		pthread_mutex_unlock(&mutex);
		return;
	}
	
	//ERR_MSG("-------------\nDEBUG/ begining callback\n");

	memset(pktinfo, 0, sizeof(packet_info));
 
	//ERR_MSG("DEBUG/ calling parse_packet().\n");
  	int ret = parse_packet(packet, pkthdr, pktinfo);

	if(ret){
		//ERR_MSG("DEBUG/ finish callback. Invalid packet.\n");
		pthread_mutex_unlock(&mutex);
		return;
	}

	if(pktinfo->request == -1){ //NI GET NI RESPONSE
		//ERR_MSG("DEBUG/ finish callback. Invalid packet II.\n");
		pthread_mutex_unlock(&mutex);
		return;
	}

	if(insertPacket(pktinfo) != 0){
		decrement_inserts();
	}
	 
    increment_inserts();

	//ERR_MSG("DEBUG/ finish callback\n");
	
    pthread_mutex_unlock(&mutex);
}

//////ADDED

uint32_t *variance_data = NULL;
int variance_packets = 0;

// void inspect_PCAP_File_Callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet){

// 	if(variance_packets < 800000){
// 		memset(pktinfo, 0, sizeof(packet_info));
// 		parse_packet(packet, pkthdr, pktinfo);
		
// 		if(pktinfo->request == 1){ //GET o POST
	
// 			if(insertPacket(pktinfo) != 0){
// 				decrement_inserts();
// 			}else{
// 				increment_inserts();
// 				variance_packets++;
// 				variance_data[variance_packets] = getIndex(pktinfo);
// 			}
// 		}

// 	}else{
// 		NDLTbreakloop(ndldata);
// 		NDLTclose(ndldata);
// 		ndldata = NULL;
// 	}
// }

int indexCompareFunction(const void *a, const void *b){
	return ( *(uint32_t*)a - *(uint32_t*)b);
}

// int inspect_PCAP_File(){

// 	//IF FILE BIG ENOUGH
// 	// FILE *f = fopen(options.input, "rb");
// 	// fseek(f, 0L, SEEK_END);
// 	// long sz = ftell(f);
// 	// rewind(f);
// 	// fclose(f);

// 	// if(sz < 4294967296){ //file size < 4GB
// 	// 	return 0;
// 	// }

// 	variance_data = (uint32_t*) calloc(800000, sizeof(uint32_t));

// 	char errbuf[PCAP_ERRBUF_SIZE] = {0};

// 	ndldata = NDLTabrirTraza(options.input, format, filter, 0, errbuf);

// 	if(NDLTloop(ndldata, inspect_PCAP_File_Callback, NULL) != 1){
// 		fprintf(stderr, "Error reading the file. Check parameters.\n");
// 		exit(1);
// 	}
	
// 	int i = 0;
		
// 	qsort(variance_data, variance_packets, sizeof(uint32_t), indexCompareFunction);
// 	int64_t last_index = -1;
// 	uint32_t index = 0;

// 	double mean = 0;
// 	double variance = 0;
// 	int total = 0;
// 	int sum = 0;
// 	int n_col = 0;


// 	for(i=0; i<800000; i++){
// 		index = variance_data[i];
// 		if(index > last_index){
// 			int n = session_table[index].n;
// 			total += n;
// 			if(n>1){
// 				n_col++;
// 				variance += n * n;
// 				sum += n;
// 			}
// 			last_index = index;
// 		}
// 	}

// 	mean = sum / ((double) n_col);
// 	variance = (variance + (sum * sum)/n_col) / ((double) (n_col-1));

// 	fprintf(stderr, "Mean: %f\tVariance:%f\tSt.Dv:%f\n", mean, variance, sqrt(variance));

// 	if(sqrt(variance) > 3){
// 		resized_session_table = 1;
// 		fprintf(stderr, "HASH TABLE RESIZED FROM 2^24 to 2^30 !\n");
// 	}

// 	reset();

// 	FREE(variance_data);
// 	ndldata = NULL;
// 	return 0;
// }

void reset(){
	freeNodelPool();
	freeConnectionPool();
	freeRequestPool();
	http_free_packet(&http);
	FREE(session_table);
	FREE(pktinfo);

	active_session_list_size = 0;
	max_active_session_list_size = 0;
	active_session_list = NULL;

	reset_counters();

	//HTTP
	http_alloc(&http);
	//NEW
	allocConnectionPool();
	allocRequestPool();
	// allocResponsePool();
	allocNodelPool();
	pktinfo = (packet_info *) calloc(sizeof(packet_info), 1);

	// if(resized_session_table){
	// 	session_table = (collision_list*) calloc(BIG_MAX_FLOWS_TABLE_SIZE, sizeof(collision_list));	
	// }else{
	session_table = (collision_list*) calloc(MAX_FLOWS_TABLE_SIZE, sizeof(collision_list));	
	// }
}


///////END ADDED

int main(int argc, char *argv[]){

	fprintf(stderr, "httpDissector: %s\n", version);
	
	//GET 
	//POST
	//HEAD
	//PUT
	//DELETE
	//PATCH
	//TRACE
	//OPTIONS
	//HTTP

	filter = strdup("tcp and ((tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420 \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x5445) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4820) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x54524143 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4520) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x4f4e5320) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x434f4e4e && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x45435420) \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450))");

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
		switch (options.filter_mode){
			case OR:
				filter = (char *) realloc(filter, (strlen(filter) + strlen(options.filter) + 6)*sizeof(char));
				strcat(filter, " or ");
				strcat(filter, options.filter);
				break;
			case AND:
				{
				char *filter_aux = (char *) calloc((strlen(filter) + strlen(options.filter) + 6), sizeof(char));
				
				strcat(filter_aux, options.filter);
				strcat(filter_aux, " and ");
				strcat(filter_aux, filter);

				char *aux = filter;
				filter = filter_aux;
				free(aux);
				}
				break;
			case OVERWRITE:
				free(filter);
				filter = strdup(options.filter);
				break;
		}
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
		fprintf(stderr, "DEBUG/ Filter: %s\n", filter);
		fprintf(stderr, "\n");
	}

	if(options.output != NULL){
		if(options.binary){
			output = fopen(options.output, "wb");
		}else{
			output = fopen(options.output, "w");	
		}
		
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

	// if(options.index != NULL){
	// 	index_file = fopen(options.index, "w");
	// 	if(index_file == NULL){
	// 		fprintf(stderr, "ERROR TRYING TO OPEN THE INDEX FILE\n");
	// 		FREE(filter);
	// 		return -8;
	// 	}
	// }

	if(options.files){
		files_path = parse_list_of_files(options.input, &nFiles);
		if(files_path == NULL){
			fprintf(stderr, "Failure parsing list of files\n");
			return -1;
		}
	}

	//INICIALIZO TABLA
	session_table = (collision_list*) calloc(MAX_FLOWS_TABLE_SIZE, sizeof(collision_list));	


	//HTTP
	http_alloc(&http);

	//NEW
	allocConnectionPool();
	allocRequestPool();
	// allocResponsePool();
	allocNodelPool();

	//PACKET_INFO
	pktinfo = (packet_info *) calloc(sizeof(packet_info), 1);
	
	//SORTED PRINT LIST
	if(options.sorted){
		initPrintElementList();
	}

	//USING INDEX FILE
	if(options.index != NULL && !options.files){
		intervals = read_index(options.index, options.input, &interval_ctr);
		if(interval_ctr == 0){
			fprintf(stderr, "\nFile not big enough to use indices.\n\n");
			options.index = NULL;
		}
	}

	main_process(format, options.input);

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

	if(options.index!=NULL){
		FREE(intervals);
	}

	// freeConnectionPool();
	// freeRequestPool();
	// freeNodelPool();

	FREE(session_table);

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
	    	syslog (LOG_NOTICE, "MEM secs memory (kb)");
	    	memory = malloc(sizeof(struct rusage));
    	}
	}

	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	
	if(options.hpcap != -1){
		hpcap_packet_online_loop(options.hpcap, options.hpcap_ifindex, options.hpcap_qindex, hpcap_callback, NULL);
		exit(-1);
	}else if(options.interface == NULL){
		
		ERR_MSG("DEBUG/ Before calling NDLTabrirTraza()\n");

	  	if(options.files){
			ndldata = NDLTabrirTraza(filename, format, filter, 1, errbuf);
		}else{
			ndldata = NDLTabrirTraza(filename, format, filter, 0, errbuf);
		}

		if(ndldata == NULL){
			fprintf(stderr, "NULL WHILE OPENING NDL FILE: %s\n", errbuf);
			fprintf(stderr, "File: %s\tRAW flag = %s\n", options.input, options.raw == 0? "false" : "true");
			return -1;
		}

		if(options.discards!=NULL){
			if(!NDLTopenFileDiscards(ndldata, options.discards, errbuf)){
				fprintf(stderr, "ERROR WHILE OPENING DISCARDS FILE (%s): %s\n", options.discards, errbuf);
				return -1;
			}
		}


		ERR_MSG("DEBUG/ After calling NDLTabrirTraza()\n");
		
	}else{ //READ FROM INTERFACE

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
		int ret = 0;
		if(options.index != NULL && !options.files){
			ret = NDLTsetIndexFile(ndldata, options.index);
			if(ret != 1){
				fprintf(stderr, "ERROR LOADING INDEX FILE IN NDleeTrazas\n");
				exit(-1);
			}
			ret = NDLTloop(ndldata, index_callback, NULL);
		}else{
			ret = NDLTloop(ndldata, callback, NULL);
		}

		if(ret != 1){
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

	total_packets_in_file = NDLTpktNumber(ndldata);

  	if(options.interface == NULL && progress_bar){
  		pthread_join(progress, NULL);
  		if(options.index != NULL){
			loadBar(ftello(NDLTfile(ndldata)), ndldata->bytesTotalesFicheros, ndldata->bytesTotalesFicheros, 40);
  		}else{
  			loadBar(ndldata->bytesTotalesLeidos, ndldata->bytesTotalesFicheros, ndldata->bytesTotalesFicheros, 40);
  		}
  		NDLTclose(ndldata);
  	}

  	if(options.sorted){
		freePrintElementList();
	}

	long elapsed = end.tv_sec - start.tv_sec;
	print_info(elapsed);

	return 0;
}

void print_info(long elapsed){
	
	setlocale(LC_ALL, "en_US"); 

	setvbuf(stderr, NULL, _IONBF, 0);

	if(options.interface){
		struct pcap_stat ps;
 		pcap_stats(handle, &ps);
		fprintf(stderr, "\nPCAP STATS: recv: %u; drop: %u; ifdrop: %u", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
	}
	
	fprintf(stderr, "\n\nFile: %s \nTotal packets in file: %'ld (Processed packets: %'ld)\n", global_filename == NULL? options.interface : global_filename, total_packets_in_file, packets);
	
	if(elapsed != 0){
		// fprintf(stderr, "Speed: %.3Lf Packets/sec (%.3Lf)\n", packets == 0 ? 0 : ((long double)packets)/elapsed, total_packets_in_file == 0 ? 0 : ((long double)total_packets_in_file)/elapsed);
		fprintf(stderr, "Speed: %'.3Lf Packets/sec (%'.3Lf Processed Packets/sec)\n", total_packets_in_file == 0 ? 0 : ((long double)total_packets_in_file)/elapsed, packets == 0 ? 0 : ((long double)packets)/elapsed);
		if(options.log){
			syslog (LOG_NOTICE, "Speed: %'.3Lf Packets/sec (%'.3Lf Processed Packets/sec)\n", total_packets_in_file == 0 ? 0 : ((long double)total_packets_in_file)/elapsed, packets == 0 ? 0 : ((long double)packets)/elapsed);
		}
	}	

	fprintf(stderr, "\nTotal Responses: %lld\n", get_total_responses());
	fprintf(stderr, "Responses without request: %f%% (%lld)\n", get_responses_without_request_ratio(), get_total_responses()-get_transactions());
	fprintf(stderr, "Responses out of order: %lld\n", get_total_out_of_order());

	fprintf(stderr, "\nREQUEST STATS %s\n", options.noRtx ? "(RTx removed)" : "");
	fprintf(stderr, "GET: %lld\n", get_get_requests());
	fprintf(stderr, "POST: %lld\n", get_post_requests());
	fprintf(stderr, "HEAD: %lld\n", get_head_requests());
	fprintf(stderr, "PATCH: %lld\n", get_patch_requests());
	fprintf(stderr, "PUT: %lld\n", get_put_requests());
	fprintf(stderr, "DELETE: %lld\n", get_delete_requests());
	fprintf(stderr, "OPTIONS: %lld\n", get_options_requests());
	fprintf(stderr, "CONNECT: %lld\n", get_connect_requests());
	fprintf(stderr, "TRACE: %lld\n\n", get_trace_requests());

	fprintf(stderr, "Total Requests: %lld\n", get_total_requests());
	if(options.noRtx){
		fprintf(stderr, "\nTotal Transactions: %lld with a %f%% of Rtx (%lld)\n", get_transactions(), get_rtx_ratio(), get_total_rtx());
	}else{
		fprintf(stderr, "\nTotal Transactions: %lld\n", get_transactions());
	}
	
	fprintf(stderr, "\nRequests without response: %f%% (%lld)\n\n", get_requests_without_response_lost_ratio(), get_total_requests()-get_transactions());
	
	fprintf(stderr, "Max. hash table usage: %"PRIu32"\n", max_active_session_list_size);

	fprintf(stderr, "Packets from %ld.%09ld to %ld.%09ld\n", first_packet.tv_sec, first_packet.tv_nsec, last_packet.tv_sec, last_packet.tv_nsec);

	return;
}
