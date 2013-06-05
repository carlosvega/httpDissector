#include "httpDissector.h"
#include "util.h"
#include "tslist.h"
#include "tools.h"
#include "http.h"
#include "args_parse.h"

struct timespec last_packet;
// GMutex *table_mutex = NULL;
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

char *filter = NULL;

int main_process(char *format, struct bpf_program fp, char *filename);

void sigintHandler(int signal){
	
	// if(options.interface == NULL){
	// 	g_thread_join(progreso);
	//   	g_thread_unref(progreso);
	// }

	// if(options.collector){
	// 	g_thread_join(recolector);
	// 	g_thread_unref (recolector);
 //  	}

	running = 0;

	// NDLTclose(ndldata);

	// g_hash_table_destroy(table);
	// // g_mutex_clear(table_mutex);
	free(filter);
	if(options.interface == NULL)
		fclose(pcapfile);

	fprintf(stderr,"\n\n");
	fprintf(stderr, "TOTAL PACKETS: %ld TOTAL PARSE TIME: %lld AVG. PARSE TIME: %lld \n", packets, parse_time, packets == 0 ? 0 : parse_time/packets);
	fprintf(stderr, "TOTAL INSERTS: %lld TOTAL INSERT TIME: %lld AVG. INSERT TIME: %lld \n", inserts, insert_time, inserts == 0 ? 0 : insert_time/inserts);
	fprintf(stderr, "Response lost ratio (Requests without response): %Lf%%\n", requests == 0 ? 0 : (((long double)lost) / requests)*100);

	exit(0);
}

gboolean hash_check_time (gpointer key, gpointer value, gpointer user_data){
  hash_value *hashvalue = (hash_value *) value;

  if(hashvalue!=NULL){
  		struct timespec diff = tsSubtract(last_packet, hashvalue->last_ts);
  	if(diff.tv_sec > 60){
  		 //fprintf(stderr, "(%d)\t(%ld,%ld)\t(%ld,%ld)\t|%.40s|\n", hashvalue->n_peticiones, hashvalue->last->ts_request.tv_sec, hashvalue->last->ts_request.tv_usec, hashvalue->last->ts_last_response.tv_sec, hashvalue->last->ts_last_response.tv_usec, hashvalue->peticiones->request);
  		 //fprintf(stderr, "YEAH! - (%ld,%ld) (%ld,%ld)", res_respuesta.tv_sec, res_respuesta.tv_usec, nids_last_pcap_header->ts.tv_sec, nids_last_pcap_header->ts.tv_usec);
  		
  		lost += hashvalue->n_request - hashvalue->n_response;

  		return TRUE;
  	}

  	//fprintf(stderr, "(%d) (%d)\t(%ld,%ld)\t(%ld,%ld)\t|%.50s|\n", hashvalue->n_peticiones, hashvalue->last->chunks, hashvalue->last->ts_request.tv_sec, hashvalue->last->ts_request.tv_usec, hashvalue->last->ts_last_response.tv_sec, hashvalue->last->ts_last_response.tv_usec, hashvalue->peticiones->request);

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

void loadBar(unsigned long x, unsigned long n, unsigned long r, int w)
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
  	//my_time = gmtime(&elapsed.tv_sec);
  	//strftime(elapsed_time, 30, "%H:%M:%S", my_time);
  	// fprintf(stderr, " Elapsed Time: (%ld %.2ld:%.2ld:%.2ld)", (elapsed.tv_sec/86400), (elapsed.tv_sec/3600)%60, (elapsed.tv_sec/60)%60, (elapsed.tv_sec)%60);

  	
	fprintf(stderr, " Elapsed Time: (%ld %.2ld:%.2ld:%.2ld) Read Speed: %ld MB/s", (elapsed.tv_sec/86400), (elapsed.tv_sec/3600)%60, (elapsed.tv_sec/60)%60, (elapsed.tv_sec)%60, elapsed.tv_sec == 0 ? 0 : x/(elapsed.tv_sec*1024*1024));
	
	if(options.log){
		syslog (LOG_NOTICE, "SPEED %ld\t%ld", elapsed.tv_sec, elapsed.tv_sec == 0 ? 0 : x/(elapsed.tv_sec*1024*1024));

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
  
  static long sleeptime = 5000000;

  if(options.raw == 1){
  	pcapfile = ndldata->traceFile.fh;
  }else{
  	pcapfile = pcap_file(ndldata->traceFile.ph);
  }

  if(options.log){
		sleeptime = 2000000;
  }

  static unsigned long pcap_position = 0;
	while(running){
		pcap_position = ftell(pcapfile);
		if(pcap_position == -1L) break;
		loadBar(pcap_position, pcap_size, pcap_size, 40);
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

	// char get[4] = "GET ";
	// char resp[4] = "HTTP";

	// if(memcmp(pktinfo->payload, get, 4) == 0){
	// 	pktinfo->request = 1;
	// }else if(memcmp(pktinfo->payload, resp, 4) == 0){
	// 	pktinfo->request = 0;
	// }else{
	// 	pktinfo->request = -1;
	// }

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
			//pktinfo->url = (char *) malloc((t_host+t_uri+1)*sizeof(char));
			memcpy(pktinfo->url, host, t_host);
			memcpy(pktinfo->url+t_host, uri, t_uri);
			// fprintf(stdout, "%s%s\n", host,uri);
		}else{
			//pktinfo->url = strdup(uri);
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

	// print_packet(p->request);
	// print_packet(p->response);

	char *ts_get = NULL;
	char *ts_res = NULL;
	ts_res = timeval_to_char(p->response->ts);
	ts_get = timeval_to_char(p->request->ts);

   	struct timespec diff = tsSubtract(p->response->ts, p->request->ts);
	
	if(options.twolines){
		fprintf(output, "GET \t%s:%i\t==>\t%s:%i\t%s %s\n", p->request->ip_addr_src, p->request->port_src, p->request->ip_addr_dst, p->request->port_dst, ts_get, p->request->url);
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
		//fprintf(stderr, "RESPONSE SIN ENTRADA EN LA TABLA\n");
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
	if(pktinfo->request == 1){ //GET
		if(insert_get_hashtable(pktinfo) != 0){
			free(pktinfo->url);
			free(pktinfo);
			fprintf(stderr, "ERROR INSERTANDO GET\n");
		}
	}else if(pktinfo->request == 0){ //RESPONSE
		if(insert_resp_hashtable(pktinfo) != 0){
			free(pktinfo);//fprintf(stderr, "ERROR INSERTANDO RESPONSE\n");
		}
	}
	g_static_mutex_unlock(&table_mutex);
  
    gettimeofday(&t4, NULL);
    insert_time += ((t4.tv_usec - t3.tv_usec)  + ((t4.tv_sec - t3.tv_sec) * 1000000.0f));
    inserts++;

	//print_packet(pktinfo);
	fflush(stderr);
	//free(pktinfo);
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
	

	char format[8] = {0};
	struct bpf_program fp;

	filter = strdup("tcp and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450)");

	options = parse_args(argc, argv);
	if(options.err == -3){
		how_to_use(argv[0]);
		free(filter);
		return 0;
	}
	if(options.err < 0){
		fprintf(stderr, "Error: %s\n", options.errbuf);
		how_to_use(argv[0]);
		free(filter);
		return -1;
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

	if(options.output != NULL){
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
		unsigned int nfiles = 0;
		char **files = NULL;
		files = parse_list_of_files(options.input, &nfiles);
		if(files == NULL){
			free(filter);
			return 0;
		}else{
			int i=0;
			fprintf(stderr, "Total Files: %d\n", nfiles);
			for(i=0; i<nfiles; i++){
				fprintf(stderr, "(%d/%d) Current File: %s\n", i, nfiles, files[i]);
				int pid = fork();
				if(pid == 0){ 			//CHILD
					main_process(format, fp, files[i]);
					int j=0;
					for(j=i; j<nfiles; j++){
						free(files[j]);
					}
					free(files);
					free(filter);
					return 0;
				}else if(pid == -1){ 	//ERROR
					fprintf(stderr, "ERROR ON FORK\n");
				}else{ 					//PARENT
					waitpid(pid, NULL, 0);
				}
				free(files[i]);
			}
			free(files);
		}
	}else{
		main_process(format, fp, options.input);
	}
	
	free(filter);

	return 0;

}

int main_process(char *format, struct bpf_program fp, char *filename){

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


	char errbuf[PCAP_ERRBUF_SIZE];
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

		struct timeval t, t2;  
		gettimeofday(&t, NULL);
		fseek(pcapfile, 0L, SEEK_END);
		gettimeofday(&t2, NULL);
		pcap_size = ftell(pcapfile);
		rewind(pcapfile); 
		fclose(pcapfile);

		long microsegundos = ((t2.tv_usec - t.tv_usec)  + ((t2.tv_sec - t.tv_sec) * 1000000.0f));
	  	fprintf(stderr, "SIZE: %ld, Time: (%ld)\n", pcap_size, microsegundos);

		ndldata = NDLTabrirTraza(filename, format, filter, 0, errbuf);
		
		if(ndldata == NULL){
			fprintf(stderr, "NULL WHILE OPENING NDL FILE: %s\n%s", errbuf, filename);
			fprintf(stderr, "%s\n%s\n%s\n%d\n", filename, options.output, options.filter, options.raw);
			free(filter);
			// if(options.log){
			// 	closelog ();
			// }
			return -1;
		}
	}else{
		handle = pcap_open_live(options.interface, SNAPLEN, PROMISC, to_MS, errbuf);
		if(handle == NULL){
			fprintf(stderr, "Couldn't open device %s: %s\n", options.interface, errbuf);
		 // 	if(options.log){
			// 	closelog ();
			// }
		 	return -2;
		}

		if(pcap_compile(handle, &fp, filter, 1, 0) == -1){
			fprintf(stderr, "Couldn't parse filter, %s\n|%s|", pcap_geterr(handle), filter);
			fclose(pcapfile);
			// if(options.log){
			// 	closelog ();
			// }
			return -3;
		}

		if(pcap_setfilter(handle, &fp) == -1){
			fprintf(stderr, "Couldn't install filter, %s\n", pcap_geterr(handle));
			fclose(pcapfile);
			// if(options.log){
			// 	closelog ();
			// }
			return -4;
		}
	}

	//inicializamos el soporte para hilos en glib
	//g_thread_supported() is actually a macro
	if(!GLIB_CHECK_VERSION (2, 32, 0)){
		if (!g_thread_supported ()) g_thread_init (NULL);
	}
	//g_assert (table_mutex == NULL);
   	// table_mutex = g_mutex_new ();
   	//g_mutex_init(table_mutex);

   	//TABLA HASH
	table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, funcionLiberacion);
	if(table == NULL){
		fprintf(stderr, "Error al crear tabla hash.");
		fclose(pcapfile);
		// if(options.log){
		// 	closelog ();
		// }
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

	//BARRA DE PROGRESO
	if(options.interface == NULL){
		if (!GLIB_CHECK_VERSION (2, 32, 0)){
			progreso = g_thread_create( (GThreadFunc)barra_de_progreso, NULL , TRUE, NULL);
		}else{
			progreso = g_thread_new("barra de progreso", (GThreadFunc)barra_de_progreso, NULL);
		}
	}

	signal(SIGINT, sigintHandler);

	struct timeval end;


	running = 1;

	if(options.interface == NULL){
		NDLTloop(ndldata, callback, NULL);
	}else{
		pcap_loop(handle, -1, online_callback, NULL);
	}

	gettimeofday(&end, NULL);
	running = 0;
	long pcap_loop = ((end.tv_usec - start.tv_usec)  + ((end.tv_sec - start.tv_sec) * 1000000.0f));

	if(options.output != NULL){
		fclose(output);
	}

	if(options.collector){
		g_thread_join(recolector);
		if (GLIB_CHECK_VERSION (2, 32, 0)){
			g_thread_unref (recolector);
		}
  	}

  	if(options.interface == NULL){
  		NDLTclose(ndldata);
  		loadBar(pcap_size, pcap_size, pcap_size, 40);
  	}

	long elapsed = end.tv_sec - start.tv_sec;


	fprintf(stderr,"\n\n");
	fprintf(stderr, "TOTAL PACKETS: %ld TOTAL PARSE TIME: %lld AVG. PARSE TIME: %lld \n", packets, parse_time, packets == 0 ? 0 : parse_time/packets);
	fprintf(stderr, "TOTAL INSERTS: %lld TOTAL INSERT TIME: %lld AVG. INSERT TIME: %lld \n", inserts, insert_time, inserts == 0 ? 0 : insert_time/inserts);
	if(elapsed != 0){
		fprintf(stderr, "%Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		if(options.log){
			syslog (LOG_NOTICE, "%Lf Packets/sec\n", packets == 0? 0 : ((long double)packets)/elapsed);
		}
	}
	
	fprintf(stderr, "Response lost ratio (Requests without response): %Lf%%\n", requests == 0 ? 0 : (((long double)lost) / requests)*100);
	fprintf(stderr, "TOTAL pcap_loop time: %ld\n", pcap_loop);
	//kill(getpid(), SIGALRM);

	// destruimos el hilo

	if(options.interface == NULL){
	  	// g_thread_join(progreso);
	  	// g_thread_unref (progreso);
  	}
  	
	//g_hash_table_foreach(table, print_foreach, NULL);

	g_hash_table_destroy(table);
	// g_mutex_free(&table_mutex);
	// g_mutex_clear(table_mutex);

	// table_mutex = NULL;
	// recolector =  NULL;
	// progreso =  NULL;
	// table = NULL;
	// ndldata = NULL;

	// if(options.log){
	// 	closelog ();
	// }

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