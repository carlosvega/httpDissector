#include "process_packet.h"

process_info *processing = NULL;
struct args_parse *options = NULL;
http_event *aux_event = NULL;

void set_filter(){

	//GET 
	//POST
	//HEAD
	//PUT
	//DELETE
	//PATCH
	//TRACE
	//OPTIONS
	//HTTP

	char *f = strdup("tcp and ((tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144 \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420 \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x5445) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4820) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x54524143 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4520) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x4f4e5320) \
		or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x434f4e4e && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x45435420) \
		or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450))");

	if(options->filter != NULL){
		switch (options->filter_mode){
			case OR:
				f = (char *) realloc(f, (strlen(f) + strlen(options->filter) + 6)*sizeof(char));
				strcat(f, " or ");
				strcat(f, options->filter);
				break;
			case AND:
				{
				char *aux = (char *) calloc((strlen(f) + strlen(options->filter) + 6), sizeof(char));
				
				strcat(aux, options->filter);
				strcat(aux, " and ");
				strcat(aux, f);

				aux = f;
				f = aux;
				free(aux);
				}
				break;
			case OVERWRITE:
				free(f);
				f = strdup(options->filter);
				break;
		}
		free(options->filter);
	}

	options->filter = f;

	return;
}

int set_read_from_interface(){	
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	processing->handle = pcap_open_live(options->interface, SNAPLEN, PROMISC, to_MS, errbuf);
	if(processing->handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", options->interface, errbuf);
	 	return -2;
	}

	if(pcap_compile(processing->handle, &fp, options->filter, 1, 0) == -1){
		fprintf(stderr, "Couldn't parse filter, %s\n|%s|", pcap_geterr(processing->handle), options->filter);
		return -3;
	}

	if(pcap_setfilter(processing->handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter, %s\n", pcap_geterr(processing->handle));
		return -4;
	}

	return 0;
}

int set_read_from_files(){
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	if(options->files){ //MULTIPLE FILES
		processing->ndldata = NDLTabrirTraza(options->input, options->format, options->filter, 1, errbuf);
	}else{ //SOLE FILE
		processing->ndldata = NDLTabrirTraza(options->input, options->format, options->filter, 0, errbuf);
	}

	if(processing->ndldata == NULL){ //ERROR OPENINF FILE
		fprintf(stderr, "NULL WHILE OPENING NDL FILE: %s\n", errbuf);
		fprintf(stderr, "File: %s\tRAW flag = %s\n", options->input, options->raw == 0? "false" : "true");
		return -1;
	}

	if(options->raw != 1){ //PRINT SNAPSHOT LENGTH
		fprintf(stderr, "Snapshot length: %d\n", pcap_snapshot(processing->ndldata->traceFile.ph));
	}

	if(options->discards!=NULL){ //OPEND DISCARDS FILE
		if(!NDLTopenFileDiscards(processing->ndldata, options->discards, errbuf)){
			fprintf(stderr, "ERROR WHILE OPENING DISCARDS FILE (%s): %s\n", options->discards, errbuf);
			return -1;
		}
	}
	return 0;
}

hash_key last_key = {0};
int parse_packet(const u_char *packet, const struct NDLTpkthdr *pkthdr){

	// if(last_key.ip_src != 0){
	// 	http_event **pre_event = get_event_from_table(&last_key);
	// 	unsigned char ip_client[4] = {0};
 //        unsigned char ip_server[4] = {0};
 //        *(unsigned int *) ip_client = (*pre_event)->key.ip_src;
 //        *(unsigned int *) ip_server = (*pre_event)->key.ip_dst;
	// 	fprintf(options->output_file, "PRE_EVENT: %d.%d.%d.%d|%i|%d.%d.%d.%d|%i|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s|%s|%s\n", 
 //                ip_client[0], ip_client[1], ip_client[2], ip_client[3], 
 //                (*pre_event)->key.port_src, ip_server[0], ip_server[1], ip_server[2], ip_server[3], 
 //                (*pre_event)->key.port_dst, (*pre_event)->ts_req.tv_sec, (*pre_event)->ts_req.tv_nsec, (*pre_event)->ts_res.tv_sec, (*pre_event)->ts_res.tv_nsec, 
 //                RESP_MSG_SIZE, (*pre_event)->response_msg, (*pre_event)->response_code, http_op_to_char((*pre_event)->method), (*pre_event)->agent, (*pre_event)->host, (*pre_event)->url);  
	// }

	packet_info pktinfo;
	size_t size_ethernet = SIZE_ETHERNET;
	memset(pktinfo.url, 0, URL_SIZE);
	pktinfo.ethernet = (struct sniff_ethernet*)(packet);
	//VLAN
	if (pktinfo.ethernet->ether_type == 0x81){
		size_ethernet += 4;	
	}

	pktinfo.ip = (struct sniff_ip*)(packet + size_ethernet);
	pktinfo.size_ip = IP_HL(pktinfo.ip)*4;

	if (pktinfo.size_ip < 20) {
		return -1;
	}

	if(pkthdr->caplen < (size_ethernet + pktinfo.size_ip + 20)){
		return -1;
	}

	pktinfo.tcp = (struct sniff_tcp*)(packet + size_ethernet + pktinfo.size_ip);
	pktinfo.size_tcp = TH_OFF(pktinfo.tcp)*4;

	pktinfo.port_src = ntohs(pktinfo.tcp->th_sport);       /* source port */
	pktinfo.port_dst = ntohs(pktinfo.tcp->th_dport);       /* destination port */

	pktinfo.tcp->th_seq = ntohl(pktinfo.tcp->th_seq);
 	pktinfo.tcp->th_ack = ntohl(pktinfo.tcp->th_ack);
    
    if (pktinfo.size_tcp < 20) {
	    return -1;
    }

    pktinfo.payload = (u_char *)(packet + size_ethernet + pktinfo.size_ip + pktinfo.size_tcp);
    pktinfo.size_payload = pkthdr->caplen - size_ethernet - pktinfo.size_ip - pktinfo.size_tcp;
    pktinfo.ts.tv_sec = pkthdr->ts.tv_sec;
    pktinfo.ts.tv_nsec = pkthdr->ts.tv_nsec;

    //FILL HASH KEY
    hash_key key;
    http_op op = check_op_from_payload(pktinfo.payload, (int) pktinfo.size_payload);
    if(op == RESPONSE){ //RESPONSE
    	key.ip_dst   = pktinfo.ip->ip_src.s_addr; //SRC STORED ON DST
		key.ip_src   = pktinfo.ip->ip_dst.s_addr; 
		key.port_dst = pktinfo.port_src; 
		key.port_src = pktinfo.port_dst;
		key.ack_seq  =  pktinfo.tcp->th_seq; //RESPONSE STORES THE SEQ
    }else if(op == ERR){ //ERR
    	return -1;
	}else{ //REQUEST
		key.ip_src   = pktinfo.ip->ip_src.s_addr; 
		key.ip_dst   = pktinfo.ip->ip_dst.s_addr; 
		key.port_src = pktinfo.port_src; 
		key.port_dst = pktinfo.port_dst;
		key.ack_seq  = pktinfo.tcp->th_ack; //REQUEST STORES THE ACK
	}

	//GET HTTP EVENT
	http_event *event = get_event_from_table(&key);
	if(event == NULL){
		return -1; //ERROR
	}

	//FILL IF EMPTY
	if(event->status == EMPTY){
		event->key.ip_src   = key.ip_src  ;
		event->key.ip_dst   = key.ip_dst  ;
		event->key.port_src = key.port_src;
		event->key.port_dst = key.port_dst;
		event->key.ack_seq  = key.ack_seq ;
	}

	if(op == RESPONSE && event->status == EMPTY){ //RESPONSE WITHOUT REQUEST
		// remove_event_from_table(&event->key);
		return 1;
	}

	// http_status old_status = (*event)->status;

	if(http_fill_event(pktinfo.payload, (int) pktinfo.size_payload, event, op) == -1){
		//TODO: CHECK WHAT TO DO WITH THE EVENT
		// fprintf(stderr, "http_fill_event2 ERROR !\n");
		remove_event_from_table(&event->key);
		return -1; //ERROR
	}

	if(op != RESPONSE){ //REQUEST
		event->ts_req.tv_sec  = pkthdr->ts.tv_sec;
		event->ts_req.tv_nsec = pkthdr->ts.tv_nsec;
	}else{ //RESPONSE
		event->ts_res.tv_sec  = pkthdr->ts.tv_sec;
		event->ts_res.tv_nsec = pkthdr->ts.tv_nsec;
	}

	//DISCARD IF URL/HOST FILTERS DO NOT APPLY
	//THIS APPLIES WETHER THE TRANSACTION IS COMPLETED 
	//OR THE REQUEST IS WAITING A RESPONSE.
	if(op != RESPONSE){
		if(options->url != NULL){
			if(boyermoore_search(event->url, options->url) == NULL){
				//TODO: WHAT TO DO WITH THE EVENT?
				remove_event_from_table(&event->key);
				return 0;
			}
		}

		if(options->host != NULL){
			if(boyermoore_search(event->host, options->host) == NULL){
				//TODO: WHAT TO DO WITH THE EVENT?
				remove_event_from_table(&event->key);
				return 0;
			}
		}
	}

	if(event->status == TRANSACTION_COMPLETE){
		//IPS TO PRETTY PRINT NUMBER VECTOR
        print_http_event(event, options->output_file);
		//TODO: PRINT INFORMATION
		//DELETE EVENT AFTER PRINT
		remove_event_from_table(&event->key);
	}

	//TODO:
	// el modulo http debe ser quien rellene el evento para evitar copias secundarias
	// comprobar lo que esta esperando
	// si al acabar el proceso la transaccion esta completa
	// imprimir los datos y eliminarla del pool

	// last_key.ip_src   = key.ip_src  ;
	// last_key.ip_dst   = key.ip_dst  ;
	// last_key.port_src = key.port_src;
	// last_key.port_dst = key.port_dst;
	// last_key.ack_seq  = key.ack_seq ;

	return 1;
}

void callback(u_char *useless, const struct NDLTpkthdr *pkthdr, const u_char* packet){
	pthread_mutex_lock(&processing->mutex); //LOCK MUTEX 

	//TODO: IF USAGE OF POOL IS HIGH, REMOVE OLD ACTIVE EVENTS
	
	//FIRST PACKET, PRINT INFO
	if(processing->first_packet.tv_sec == 0){
		processing->first_packet = pkthdr->ts;
		fprintf(stderr, "First Packet. Caplen: %"PRIu32", Len: %"PRIu32"\n", pkthdr->caplen, pkthdr->len);
	}
	
	//STATS
	if(pkthdr->caplen > processing->max_caplen){
		processing->max_caplen = pkthdr->caplen;
	}

	//STATS
	if(pkthdr->len > processing->max_len){
		processing->max_len = pkthdr->len;
	}

	//LAST TS
	processing->last_packet = pkthdr->ts;
	processing->packets++;
  	int ret = parse_packet(packet, pkthdr); 
  	//1 => OK; 0 => filtered out; -1 => ERR

  	//TODO, UPDATE STATS AND COUNTERS

	// if(ret){
	// 	pthread_mutex_unlock(&processing->mutex);
	// 	return;
	// }

	// if(pktinfo.request == -1){ //NI GET NI RESPONSE
	// 	pthread_mutex_unlock(&processing->mutex);
	// 	return;
	// }

	// if(insertPacket(pktinfo) != 0){
	// 	decrement_inserts();
	// }
	 
    // increment_inserts();

	pthread_mutex_unlock(&processing->mutex);
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

int begin_process(struct args_parse *o, process_info *p){
	processing = p;
	options = o;
	aux_event = (http_event *) calloc(sizeof(http_event), 1);

	set_filter();

	//READ FROM FILE OR FILES
	if(options->interface == NULL){
		if(set_read_from_files() != 0){
			return -1;
		}
	}else{
		if(set_read_from_interface() != 0){
			return -1;
		}
	}

	// //GARBAGE COLLECTOR
	// if(options->collector){
	// 	pthread_create(&collector, NULL, recolector_de_basura, NULL);
	// 	//running = 1;
	// }

	// //gettimeofday(&start, NULL);

	// //PROGRESS BAR
	// if(options->interface == NULL){
	// 	pthread_create(&progress, NULL, barra_de_progreso, NULL);
	// }

	//BEGIN PROCESS
	fprintf(stderr, "BEGIN PROCESS\n");
	gettimeofday(&processing->start, NULL);
	if(options->interface == NULL){
		//FROM FILE 
		int ret = NDLTloop(processing->ndldata, callback, NULL);
		if(ret != 1){
			return -1;
		}
	}else{
		//FROM INTERFACE
		pcap_loop(processing->handle, -1, online_callback, NULL);
	}
	struct timeval end;
	gettimeofday(&end, NULL);
	long elapsed = end.tv_sec - processing->start.tv_sec;
	// gettimeofday(&end, NULL);
	// remove_old_active_nodes(last_packet);
	//running = 0;


	//JOIN THREADS
	// if(options->collector){
	// 	pthread_join(collector, NULL);
 //  	}

  	if(options->interface == NULL){
  		// pthread_join(progress, NULL);
  		// loadBar(ndldata->bytesTotalesLeidos, ndldata->bytesTotalesFicheros, ndldata->bytesTotalesFicheros, 40);
  		NDLTclose(processing->ndldata);
  	}

 	// long elapsed = end.tv_sec - start.tv_sec;
	// print_info(elapsed);
  	return 0;

}





