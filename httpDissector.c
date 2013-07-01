#include "httpDissector.h"
#include "util.h"
#include "tslist.h"
#include "tools.h"
#include "http.h"
#include "args_parse.h"

char version[32] = "Version 0.89";

struct timespec last_packet;

static GStaticMutex table_mutex = G_STATIC_MUTEX_INIT;
GThread *recolector =  NULL;
GThread *progreso =  NULL;
GHashTable *table = NULL;

struct rusage* memory = NULL;

unsigned long long parse_time = 0;
unsigned long long insert_time = 0;
unsigned long long inserts = 0;
unsigned long long lost = 0;
unsigned long long requests = 0;
unsigned long transacctions = 0;

char format[8] = {0};

char *filter = NULL;

//PARALLEL PROCESSING

char **files_path = NULL;
int last_file = -1;
pid_t father_pid;
short progress_bar = 1;
char *child_filename = NULL;
char new_filename[256] = {0};

void create_process();
void handler(int sig);
int parallel_processing();
int main_process(char *format, char *filename);

void sigintHandler(int signal){

	running = 0;

	if(options.parallel){
		if(father_pid == getpid()){
			while (waitpid(-1, NULL, 0)) {
		   		if (errno == ECHILD) {
		      		break;
		   		}
			}
			return;
		}
	}

	struct timeval end;
	gettimeofday(&end, NULL);

	fprintf(stderr, "\n\nSkipping, wait...\n");

	if(filter != NULL){
		free(filter);
		filter = NULL;
	}

	if(options.interface == NULL && progress_bar){
		fclose(pcapfile);
		g_thread_join(progreso);
	}

	if(options.parallel){
		fprintf(stderr,"\n\nInput File: %s\nOutput File: %s\n", child_filename, options.output != NULL ? new_filename : "Standard Output");
	}else{
		fprintf(stderr, "\n\n");
	}
	fprintf(stderr, "Total packets: %ld\nTotal inserts: %lld\nResponse lost ratio (Requests without response): %Lf%%\n", packets, inserts, requests == 0 ? 0 : (((long double)lost) / requests)*100);

	long elapsed = end.tv_sec - start.tv_sec;

	if(elapsed != 0){
		fprintf(stderr, "Speed: %Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		if(options.log){
			syslog (LOG_NOTICE, "%Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		}
	}

	exit(0);
}

gboolean hash_check_time (gpointer key, gpointer value, gpointer user_data){
  hash_value *hashvalue = (hash_value *) value;

  if(hashvalue!=NULL){
  		struct timespec diff = tsSubtract(last_packet, hashvalue->last_ts);
  	if(diff.tv_sec > 60){
  		
  		lost += hashvalue->n_request - hashvalue->n_response;

  		return TRUE;
  	}

  }

  return FALSE;

}

GThreadFunc recolector_de_basura(){ 
	short l=0;
	//ten sleeps of 1 second, just to be able to end the thread properly
	while(l<10){ sleep(1); running == 0 ? l=10 : l++;}
	while(running){
		l=0;
	 	g_static_mutex_lock(&table_mutex);
        if (options.verbose)
        {
            fprintf(stderr, "==============================\n");
            fprintf(stderr, "Elements in table hash before removing entries: %d\n", g_hash_table_size(table));
        }
	 	unsigned int removed = g_hash_table_foreach_remove(table, hash_check_time, NULL);
        if (options.verbose)
        {
            fprintf(stderr, "Elements in table hash after removing entries: %d Removed: %u\n", g_hash_table_size(table), removed);
            fprintf(stderr, "==============================\n\n");
        }
        g_static_mutex_unlock(&table_mutex);
	 	while(l<10){ sleep(1); running == 0 ? l=10 : l++;}
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
		syslog (LOG_NOTICE, "SPEED %ld\t%lld", elapsed.tv_sec, elapsed.tv_sec == 0 ? 0 : x/(elapsed.tv_sec*1024*1024));

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
    fflush(stderr);
}

GThreadFunc barra_de_progreso(){
  
  static long sleeptime = 2000000;

  if(options.log){
		sleeptime = 2000000;
  }

  	while(running){
  		loadBar(ndldata->bytesTotalesLeidos, ndldata->bytesTotalesFicheros, ndldata->bytesTotalesFicheros, 40);
  		usleep(sleeptime);
  	}
	
	return NULL;
}

int parse_packet(const u_char *packet, const struct NDLTpkthdr *pkthdr, packet_info *pktinfo){
	pktinfo->url = NULL;
	pktinfo->ethernet = (struct sniff_ethernet*)(packet);
	pktinfo->ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	pktinfo->size_ip = IP_HL(pktinfo->ip)*4;

	if (pktinfo->size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return 1;
	}

	pktinfo->tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + pktinfo->size_ip);
	pktinfo->size_tcp = TH_OFF(pktinfo->tcp)*4;

	pktinfo->port_src = ntohs(pktinfo->tcp->th_sport);       /* source port */
	pktinfo->port_dst = ntohs(pktinfo->tcp->th_dport);       /* destination port */
      
    if (pktinfo->size_tcp < 20) {
	    //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	    return 1;
    }

    pktinfo->payload = (u_char *)(packet + SIZE_ETHERNET + pktinfo->size_ip + pktinfo->size_tcp);
    pktinfo->size_payload = pkthdr->len - SIZE_ETHERNET - pktinfo->size_ip - pktinfo->size_tcp;
    pktinfo->ts = pkthdr->ts;
	inet_ntop(AF_INET, &(pktinfo->ip->ip_src), pktinfo->ip_addr_src, 16);
    inet_ntop(AF_INET, &(pktinfo->ip->ip_dst), pktinfo->ip_addr_dst, 16);

  	http_packet http = NULL;

  	if(http_parse_packet((char*) pktinfo->payload, (int) pktinfo->size_payload, &http) == -1){
 		http_free_packet(&http);
 		return 1;
 	}

    if(pktinfo->size_payload <= 0){
    	pktinfo->request = -1;
    	return 1;
    }

    pktinfo->op = http_get_op(http);
	if(http_get_op(http) == RESPONSE){
		pktinfo->request = 0;
		pktinfo->responseCode = http_get_response_code(http);
		strcpy(pktinfo->response_msg, http_get_response_msg(http));
	}else if(http_get_op(http) == GET){
		char * host = http_get_host(http);
		size_t t_host = strlen(host);
		char * uri = http_get_uri(http);
		size_t t_uri = strlen(uri);
		pktinfo->url = (char *) calloc(2500,sizeof(char));
		if(strlen(host) != 0){
			memcpy(pktinfo->url, host, t_host);
			memcpy(pktinfo->url+t_host, uri, t_uri);
		}else{
			strcpy(pktinfo->url, uri);
		}

		if(options.url != NULL){
			if(boyermoore_search(pktinfo->url, options.url) == NULL){
				http_free_packet(&http);
				return 1;
			}
		}

		pktinfo->request = 1;
	}else if(http_get_op(http) == POST){
		char * host = http_get_host(http);
		size_t t_host = strlen(host);
		char * uri = http_get_uri(http);
		size_t t_uri = strlen(uri);
		pktinfo->url = (char *) calloc(2500,sizeof(char));
		if(strlen(host) != 0){
			memcpy(pktinfo->url, host, t_host);
			memcpy(pktinfo->url+t_host, uri, t_uri);
		}else{
			strcpy(pktinfo->url, uri);
		}

		if(options.url != NULL){
			if(boyermoore_search(pktinfo->url, options.url) == NULL){
				http_free_packet(&http);
				return 1;
			}
		}

		pktinfo->request = 1;

	}else{
		pktinfo->request = -1;
	}

	http_free_packet(&http);

	return 0;
}

void print_packet(packet_info *pktinfo){

	char *timestamp = NULL;
	char *hashkey = NULL;
	char method[5] = {0};
    timestamp = timeval_to_char(pktinfo->ts);

    if(pktinfo->request == 0){ //RESPONSE
    	strcpy(method, "RESP");
    }else if(pktinfo->request == 1){ //GET
    	strcpy(method, "GET");
    }else{
    	return;
    }
	
	fprintf(output, "%ld\t(%d)\t%.4s\t%s:%i\t-->\t%s:%i\t%s", packets, pktinfo->size_payload, method , pktinfo->ip_addr_src, pktinfo->port_src, pktinfo->ip_addr_dst, pktinfo->port_dst, timestamp);
	hashkey = hash_key(pktinfo);
	fprintf(output, "\tKEY: |%s|\n", hashkey);

	free(timestamp);
	free(hashkey);
}

int print_avg_pair(pair *p){

	if(p == NULL){
		return -1;
	}

	static long last_sec = 0;
	static struct timespec last_diff;
	static int n_diffs = 0;

	if(last_sec != p->response->ts.tv_sec){
		double d_diff = tsFloat (last_diff);
		d_diff = d_diff / ((double) n_diffs);
		fprintf(output, "%ld %f\n", last_sec, d_diff);
		last_sec = p->response->ts.tv_sec;
		last_diff.tv_sec = 0;
		last_diff.tv_nsec = 0;
		n_diffs = 0;
	}

	struct timespec diff = tsSubtract(p->response->ts, p->request->ts);	

	last_diff = tsAdd(last_diff, diff);
	n_diffs++;

	return 0;

}

int print_pair(pair *p){

	if(p == NULL){
		return -1;
	}

	transacctions++;

	if(options.rrd){
		print_avg_pair(p);
		return 0;
	}

	char *ts_get = NULL;
	char *ts_res = NULL;
	ts_res = timeval_to_char(p->response->ts);
	ts_get = timeval_to_char(p->request->ts);

   	struct timespec diff = tsSubtract(p->response->ts, p->request->ts);
	
	if(options.twolines){
		fprintf(output, "%s\t%s:%i\t==>\t%s:%i\t%s %s\n", p->request->op == POST ? "POST" : "GET", p->request->ip_addr_src, p->request->port_src, p->request->ip_addr_dst, p->request->port_dst, ts_get, p->request->url);
		fprintf(output, "RESP\t%s:%i\t<==\t%s:%i\t%s DIFF: %ld.%09ld %s %d\n", p->response->ip_addr_dst, p->response->port_dst, p->response->ip_addr_src, p->response->port_src, ts_res, diff.tv_sec, diff.tv_nsec, p->response->response_msg, p->response->responseCode);
	}else{
		fprintf(output, "%s|%i|%s|%i|%s|%s|%ld.%09ld|%s|%d|%s\n", p->request->ip_addr_src, p->request->port_src, p->request->ip_addr_dst, p->request->port_dst, ts_get, ts_res, diff.tv_sec, diff.tv_nsec, p->response->response_msg, p->response->responseCode, p->request->url);
	}

	free(ts_get);
	free(ts_res);

	return 0;
}

pair *get_request(pair **a, int n, int t){
	if(a == NULL || n>t || n<=0 ){
		return NULL;
	}

	return a[n-1];
}

int insert_get_hashtable(packet_info *pktinfo){


	if(pktinfo == NULL){
		fprintf(stderr, "PKTINFO NULL\n");
		return -1;
	} 

	char *hashkey = NULL;
	hashkey = hash_key(pktinfo);
	hash_value *hashvalue;

	gpointer gkey = NULL, gval = NULL;
	gboolean breturn = g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
	hashvalue = (hash_value *) gval;

	if(hashvalue == NULL || breturn == FALSE){ // NO ESTA EN LA TABLA
		hashvalue = (hash_value *) calloc(sizeof(hash_value), 1);
		init_list(hashvalue);
		hashvalue->list->request = pktinfo;
		hashvalue->list->response = NULL;
		hashvalue->list->next = NULL;
		hashvalue->last = hashvalue->list;
	}else if(hashvalue != NULL && breturn == TRUE){ // HAY UNA ENTRADA EN LA TABLA

		breturn = g_hash_table_steal(table, hashkey);
		if(breturn == FALSE){
			fprintf(stderr, "ERROR WHILE STEALING FROM HASH TABLE\n");
			return -1;
		}

		hashvalue->last->next = (pair *) calloc(sizeof(pair), 1);
		hashvalue->last = hashvalue->last->next;
		hashvalue->last->request = pktinfo;
		hashvalue->last->response = NULL;
		hashvalue->last->next = NULL;
	}

	//EN AMBOS CASOS
	hashvalue->n_request++;
	hashvalue->last_ts = pktinfo->ts;

	g_hash_table_insert(table, hashkey, hashvalue);

	requests++;

	if(gkey != NULL){
		free(gkey);
	}

	return 0;
}

int insert_resp_hashtable(packet_info *pktinfo){
	char *hashkey = NULL;
	int ret = 0;
	hashkey = hash_key(pktinfo);
	hash_value *hashvalue;
	gpointer gkey = NULL, gval = NULL;
	gboolean breturn = g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
	hashvalue = (hash_value *) gval;
	
	if(hashvalue == NULL || breturn == FALSE){ // NO ESTA EN LA TABLA
		free(hashkey);
		return -1;
	}else if(hashvalue != NULL && breturn == TRUE){ // HAY UNA ENTRADA EN LA TABLA
		breturn = g_hash_table_steal(table, hashkey);
		if(breturn == FALSE){
			fprintf(stderr, "ERROR STEALING FROM HASH TABLE\n");
			free(hashkey);
			return -1;
		}
		
		//BUSCAR LA PETICION CORRESPONDIENTE QUE SERA LA PRIMERA SIEMPRE
		hashvalue->n_response++;

		pair *p = hashvalue->list;
		if(hashvalue->list == NULL){
			free(hashkey);
			return -1;
		}
		
		if(p->request == NULL){
			fprintf(stderr, "ERROR, NO REQUEST FOR RESPONSE\n");
			free(hashkey);
			return -1;
		}

		p->response = pktinfo;
		hashvalue->last_ts = pktinfo->ts;
		
		print_pair(p);
		fflush(output);
		
        //ELIMINAMOS LA PETICION SATISFECHA
        ret = remove_first_node(hashvalue);
        if (ret == -1)
        {
            fprintf(stderr, "ERROR DELETING FIRST PAIR\n");
            free(hashkey);
            return -1;
        }
        else if (ret == 2)  //ERA EL ULTIMO PAR
        {
            funcionLiberacion(gval);
            free(gkey);
            free(hashkey);
            gkey = NULL;
        }
        else   //CORRECTO
        {
            g_hash_table_insert(table, hashkey, hashvalue);
        }

	}else{
		free(hashkey);
		return -1;
	}

	if(gkey != NULL){
		free(gkey);
	}

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

	last_packet = pkthdr->ts;

	packet_info *pktinfo = NULL;
	pktinfo = (packet_info *) calloc(sizeof(packet_info), 1);
	if(pktinfo == NULL){
		return;
	}
	packets++;

  struct timeval t, t2;  
  gettimeofday(&t, NULL);
 
  int ret = parse_packet(packet, pkthdr, pktinfo);

  gettimeofday(&t2, NULL);
  parse_time += ((t2.tv_usec - t.tv_usec)  + ((t2.tv_sec - t.tv_sec) * 1000000.0f));

	if(ret){
		free(pktinfo);
		return;
	}

	if(pktinfo->request == -1){ //NI GET NI RESPONSE
		free(pktinfo);
		return;
	}
  
   struct timeval t3, t4;  
   gettimeofday(&t3, NULL);
 
 	g_static_mutex_lock(&table_mutex);
	if(pktinfo->request == 1){ //GET o POST
		if(insert_get_hashtable(pktinfo) != 0){
			free(pktinfo->url);
			free(pktinfo);
			fprintf(stderr, "ERROR INSERTANDO GET\n");
		}
	}else if(pktinfo->request == 0){ //RESPONSE
		if(insert_resp_hashtable(pktinfo) != 0){
			free(pktinfo);
		}
	}
	g_static_mutex_unlock(&table_mutex);
  
    gettimeofday(&t4, NULL);
    insert_time += ((t4.tv_usec - t3.tv_usec)  + ((t4.tv_sec - t3.tv_sec) * 1000000.0f));
    inserts++;

	fflush(stderr);
}

int main(int argc, char *argv[]){

	if(glib_check_version(2, 32, 0) != NULL){
		fprintf(stderr, "Your GLIB version is: %d.%d.%d\n", glib_major_version, glib_minor_version,  glib_micro_version);
		fprintf(stderr, "You are still able to continue the execution of this program but we strongly recommend upgrading the library.\n");
	}else if(glib_check_version(2, 18, 0) != NULL){
		fprintf(stderr, "YOUR GLIB VERSION IS: %d.%d.%d\n", glib_major_version, glib_minor_version,  glib_micro_version);
		fprintf(stderr, "THE MIN. VERSION REQUIRED TO WORK IS: 2.18.0\n");
		return 0;
	}

	filter = strdup("tcp and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450)");

	options = parse_args(argc, argv);
	if(options.err == -3){
		how_to_use(argv[0]);
		free(filter);
		filter = NULL;
		return 0;
	}
	if(options.err < 0){
		fprintf(stderr, "\nError: %s\n", options.errbuf);
		how_to_use(argv[0]);
		free(filter);
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

	if(options.output != NULL && options.parallel == 0){
		output = fopen(options.output, "w");
		if(output == NULL){
			fprintf(stderr, "ERROR TRYING TO OPEN THE OUTPUT FILE\n");
			free(filter);
			return -2;
		}
	}else{
		output = stdout;
	}

	if(options.files){
		files_path = parse_list_of_files(options.input, &nFiles);
		if(files_path == NULL){
			fprintf(stderr, "Failure parsing list of files\n");
			return -1;
		}
	}
	
	if(options.parallel == 0){
		main_process(format, options.input);
	}else if(options.parallel == 1){
		fprintf(stderr, "PARALLEL PROCESSING WITH 1 PROCESS?\n");
	}else if(options.parallel > 0 && options.files == 0){
		fprintf(stderr, "PARALLEL PROCESSING WITHOUT A LIST OF FILES?\n");
	}else if(options.parallel > 0){
		parallel_processing();
	}

	if(options.output != NULL && options.parallel == 0){
		fclose(output);
	}

	if(filter != NULL){
		free(filter);
	}
	filter = NULL;
	if(files_path != NULL){
		int i=0;
		for(i=0; i<nFiles; i++){
			if(files_path[i] != NULL){
				free(files_path[i]);
			}
		}
		free(files_path);
		files_path = NULL;
	}

	return 0;

}

void create_process(){
	last_file++;

	if(last_file >= nFiles){
		running = 0;
		return;
	}

	if(!fork()) {
		fprintf(stderr, "%s child created [%s] process id is %d of %d\n", last_file%options.parallel==0 ? "+++" : "---", files_path[last_file], getpid(), getppid());
		main_process(format, files_path[last_file]);
		kill(getppid(), SIGUSR1);
		exit(0);
	}
}

void handler(int sig) {
	create_process();
}

int parallel_processing(){
	
	progress_bar = 0;
	options.files = 0;

	father_pid = getpid();

	struct sigaction act;
	act.sa_handler=handler;
	sigaction(SIGUSR1, &act, NULL);

	running = 1;

	int i;
	for(i=0; i<options.parallel; i++){
		create_process();
	}

	while(running){
		while (waitpid(-1, NULL, 0)) {
	   		if (errno == ECHILD) {
	      		break;
	   		}
		}
	}

	// struct sigaction act2;
	// act2.sa_handler=handler;
	// sigaction(SIGCHLD, &act2, NULL);
	//wait(&status);

	return 0;
}

int main_process(char *format, char *filename){

	struct bpf_program fp;

	if(options.parallel){
		child_filename = filename;
		if(options.output != NULL){
			snprintf(new_filename, 256, "%s%d", options.output, last_file);
			output = fopen(new_filename, "w");
			if(output == NULL){
				fprintf(stderr, "ERROR TRYING TO OPEN THE OUTPUT FILE %s\n", new_filename);
				return -2;
			}
		}
	}

	if(options.log){
		if(options.interface != NULL){
			options.log = 0;
		}else{
			setlogmask (LOG_UPTO (LOG_NOTICE));
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
		pcapfile = fopen(filename, "r");
		if(pcapfile == NULL){
			fprintf(stderr, "ERROR TRYING TO OPEN THE INPUT FILE |%s|\n", filename);
			if(options.log){
				closelog ();
			}
			return -2;
		}

		// struct timeval t, t2;  
		// gettimeofday(&t, NULL);
		// fseek(pcapfile, 0L, SEEK_END);
		// gettimeofday(&t2, NULL);
		// pcap_size = ftell(pcapfile);
		// rewind(pcapfile); 
		// fclose(pcapfile);

		// long microsegundos = ((t2.tv_usec - t.tv_usec)  + ((t2.tv_sec - t.tv_sec) * 1000000.0f));
	 //  	fprintf(stderr, "SIZE: %ld, Time: (%ld)\n", pcap_size, microsegundos);

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
	}else{
		handle = pcap_open_live(options.interface, SNAPLEN, PROMISC, to_MS, errbuf);
		if(handle == NULL){
			fprintf(stderr, "Couldn't open device %s: %s\n", options.interface, errbuf);
		 	return -2;
		}

		if(pcap_compile(handle, &fp, filter, 1, 0) == -1){
			fprintf(stderr, "Couldn't parse filter, %s\n|%s|", pcap_geterr(handle), filter);
			fclose(pcapfile);
			return -3;
		}

		if(pcap_setfilter(handle, &fp) == -1){
			fprintf(stderr, "Couldn't install filter, %s\n", pcap_geterr(handle));
			fclose(pcapfile);
			return -4;
		}
	}

	//inicializamos el soporte para hilos en glib
	//g_thread_supported() is actually a macro
	if(!GLIB_CHECK_VERSION (2, 32, 0)){
		if (!g_thread_supported ()) g_thread_init (NULL);
	}

   	//TABLA HASH
	table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, funcionLiberacion);
	if(table == NULL){
		fprintf(stderr, "Error al crear tabla hash.");
		fclose(pcapfile);
		return -5;
	}

	//creamos los hilos

	//RECOLECTOR
	if(options.collector){
		if (!GLIB_CHECK_VERSION (2, 32, 0)){
			recolector = g_thread_create( (GThreadFunc)recolector_de_basura, NULL , TRUE, NULL);
		}else{
			recolector = g_thread_new("recolector de basura", (GThreadFunc)recolector_de_basura, NULL);
		}
	}
	
	
	gettimeofday(&start, NULL);
	running = 1;

	//BARRA DE PROGRESO
	if(options.interface == NULL && progress_bar){
		if (!GLIB_CHECK_VERSION (2, 32, 0)){
			progreso = g_thread_create( (GThreadFunc)barra_de_progreso, NULL , TRUE, NULL);
		}else{
			progreso = g_thread_new("barra de progreso", (GThreadFunc)barra_de_progreso, NULL);
		}
	}

	signal(SIGINT, sigintHandler);

	struct timeval end;


	if(options.interface == NULL){
		if(NDLTloop(ndldata, callback, NULL) != 1){
			sigintHandler(1);
		}
	}else{
		pcap_loop(handle, -1, online_callback, NULL);
	}

	gettimeofday(&end, NULL);
	running = 0;

	if(options.collector){
		g_thread_join(recolector);
		if (GLIB_CHECK_VERSION (2, 32, 0)){
			g_thread_unref (recolector);
		}
  	}

  	if(options.interface == NULL && progress_bar){
  		g_thread_join(progreso);
  		loadBar(ndldata->bytesTotalesLeidos, ndldata->bytesTotalesLeidos, ndldata->bytesTotalesLeidos, 40);
  		NDLTclose(ndldata);
  	}

	long elapsed = end.tv_sec - start.tv_sec;


	fprintf(stderr,"\n\n");
	if(options.parallel){
		fprintf(stderr,"Input File: %s\nOutput File: %s\n", child_filename, options.output != NULL ? new_filename : "Standard Output");
		fprintf(stderr, "Total packets: %ld\nTotal inserts: %lld\nResponse lost ratio (Requests without response): %Lf%%\n", packets, inserts, requests == 0 ? 0 : (((long double)lost) / requests)*100);
	}else{
		fprintf(stderr, "File: %s \nTotal packets: %ld\nTotal inserts: %lld\nResponse lost ratio (Requests without response): %Lf%%\n", filename, packets, inserts, requests == 0 ? 0 : (((long double)lost) / requests)*100);
	}
	if(elapsed != 0){
		fprintf(stderr, "Speed: %Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		if(options.log){
			syslog (LOG_NOTICE, "%Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		}
	}
	
	if(options.parallel){
		fprintf(stderr,"\n\n");
	}

	g_hash_table_destroy(table);

	return 0;
}

void print_foreach (gpointer key, gpointer value, gpointer user_data){
	packet_info *pktinfo = (packet_info *) value;
	print_packet(pktinfo);
	return;
}

void funcionLiberacion(gpointer data){

	hash_value *hashvalue;

	hashvalue = (hash_value *) data;

	if(hashvalue == NULL) return;

	free_tslist(hashvalue);

	free(hashvalue);

	return;	
}