
#include "hashvalue.h"


extern node_l *session_table[MAX_FLOWS_TABLE_SIZE];
extern node_l *active_session_list;
extern uint32_t active_session_list_size;
extern struct timespec last_packet;

extern uint64_t last_packet_timestamp;
extern struct args_parse options;
extern unsigned long long no_cases;

extern FILE *output;

node_l static_node;

node_l *hashvalue_pool_free=NULL;
node_l *hashvalue_pool_used=NULL;

node_l *nodel_aux;

hash_value *hashvalues;
hash_value aux_hashvalue;

void removeRequestFromHashvalue(hash_value *hashvalue){

	if(list_is_empty(&hashvalue->list)){
		return;
	}

	do{
		node_l *n = list_get_first_node(&hashvalue->list);	//Obtiene el primer nodo			
		if(n->data != NULL){
			request *req = (request*) n->data;				//Obtiene la peticion de ese nodo
			
			memset(req, 0, sizeof(request));				//Resetear request
			releaseRequest(req);							//Devolver request al pool de requests
			n->data = NULL;									//data a NULL
		}
		list_unlink(&hashvalue->list, n);					//Quitamos nodo de la lista de transacciones
		releaseNodel(n);									//Devolvemos el nodo al pool
	}while(!list_is_empty(&hashvalue->list));				//Repetir hasta que este vacia

	return;
}

void allocHasvaluePool(void){
	
	int i=0;
	node_l *n=NULL;
	hashvalues=calloc(MAX_POOL_FLOW,sizeof(hash_value));
	assert(hashvalues!=NULL);
	for(i=0;i<MAX_POOL_FLOW;i++){
		n=list_alloc_node(hashvalues+i);
		list_prepend_node(&hashvalue_pool_free,n);
	}

}

hash_value * getHashvalue(void){

	//Obtiene nodo del pool con el hashvalue nuevo
	node_l *n=list_pop_first_node(&hashvalue_pool_free);

	if(hashvalue_pool_free==NULL)
	{	printf("pool Flujos vacío\n");
		exit(-1);
	}
	//Lo mete en el pool de usados
	list_prepend_node(&hashvalue_pool_used,n);

	return  (n->data); //retorna el hashvalue
	
}

void releaseHashvalue(hash_value * f)
{

	node_l *n=list_pop_first_node(&hashvalue_pool_used);
	n->data=(void*)f;
	list_prepend_node(&hashvalue_pool_free,n);


}

void freeHashvaluePool(void)
{
	node_l *n=NULL;
	while(hashvalue_pool_free!=NULL)
	{
		n=list_pop_first_node(&hashvalue_pool_free);
		free(n);
	}

	while(hashvalue_pool_used!=NULL)
	{
		n=list_pop_first_node(&hashvalue_pool_used);
		free(n);
	}
	free(hashvalues);
}


/*******************************************************
*
*  This function compares the tuples of two different IP_flows
*  returns 0 if they are equal and other thing if they are
*  different
*
********************************************************/
// int compareTupleFlow(void *a, void *b)
// {
// 	if(	(((hash_value*)a)->incoming.source_ip == ((hash_value*)b)->incoming.source_ip) &&
// 		(((hash_value*)a)->incoming.destination_ip == ((hash_value*)b)->incoming.destination_ip) &&
// 		(((hash_value*)a)->incoming.source_port == ((hash_value*)b)->incoming.source_port) &&
// 		(((hash_value*)a)->incoming.destination_port == ((hash_value*)b)->incoming.destination_port) &&
// 		(((hash_value*)a)->incoming.transport_protocol == ((hash_value*)b)->incoming.transport_protocol)
// 	)
// 	{
// 		((hash_value*)b)->actual_flow=&(((hash_value*)b)->incoming);
// 		return 0;
// 	}
	
// 	return 1;
// }

// int compareTupleFlowList(void *a, void *b)
// {
// 	IPSession *aa=((node_l*)a)->data;
// 	IPSession *bb=((node_l*)b)->data;

// 	if( 	(((IPSession*)aa)->incoming.source_ip == ((IPSession*)bb)->incoming.source_ip) &&
// 		(((IPSession*)aa)->incoming.destination_ip == ((IPSession*)bb)->incoming.destination_ip) &&
// 		(((IPSession*)aa)->incoming.source_port == ((IPSession*)bb)->incoming.source_port) &&
// 		(((IPSession*)aa)->incoming.destination_port == ((IPSession*)bb)->incoming.destination_port) &&
// 		(((IPSession*)aa)->incoming.transport_protocol == ((IPSession*)bb)->incoming.transport_protocol) 
// 	)
// 	{
// 		((IPSession*)bb)->actual_flow=&(((IPSession*)bb)->incoming);
// 		return 0;
// 	}
	
// 	return 1;
// }


// int compareTupleSession(void *a, void *b)
// {

// 	if(	(((IPSession*)a)->incoming.source_ip == ((IPSession*)b)->incoming.source_ip) &&
// 		(((IPSession*)a)->incoming.destination_ip == ((IPSession*)b)->incoming.destination_ip) &&
// 		(((IPSession*)a)->incoming.source_port == ((IPSession*)b)->incoming.source_port) &&
// 		(((IPSession*)a)->incoming.destination_port == ((IPSession*)b)->incoming.destination_port) &&
// 		(((IPSession*)a)->incoming.transport_protocol == ((IPSession*)b)->incoming.transport_protocol)
// 	)
// 	{	
// 	  	((IPSession*)b)->actual_flow=&(((IPSession*)b)->incoming);
// 	  	return 0;
//   	}
// 	else if(   	(((IPSession*)a)->incoming.source_ip == ((IPSession*)b)->outgoing.source_ip) &&
// 			(((IPSession*)a)->incoming.destination_ip == ((IPSession*)b)->outgoing.destination_ip) &&
// 			(((IPSession*)a)->incoming.source_port == ((IPSession*)b)->outgoing.source_port) &&
// 			(((IPSession*)a)->incoming.destination_port == ((IPSession*)b)->outgoing.destination_port) &&
// 			(((IPSession*)a)->incoming.transport_protocol == ((IPSession*)b)->outgoing.transport_protocol)
// 	)
// 	{
// 		  ((IPSession*)b)->actual_flow=&(((IPSession*)b)->outgoing);

//   	  	  return 0;
// 	}

// 	return 1;

// }

// IPSession *insertFlowTable(IPSession *aux_session,IPFlow *new_flow,int index)
// {
// 	node_l *new_active_node = NULL;
// 	node_l *naux = NULL;
	
// 	//lista de colisiones
// 	node_l *list=session_table[index];
// 	/*if( (new_flow->flag_ACK_nulo)==1 )  {
// 		packts_ACK_descartados++;
// 		return aux_session;
// 	}*/

// 	new_flow->previous_timestamp=last_packet_timestamp;
// 	/*If flow is not in the list, insert it*/
// 	new_flow->previous_seq_number=new_flow->current_seq_number+new_flow->dataLen;

// 	new_flow->size[0] = new_flow->nbytes;
// 	new_flow->packet_offset[0] = new_flow->offset;
// 	new_flow->timestamp[0] = last_packet_timestamp;
// 	aux_session->lastpacket_timestamp= last_packet_timestamp;
// 	aux_session->firstpacket_timestamp= last_packet_timestamp; 

// 	new_flow->max_pack_size=new_flow->nbytes;
// 	new_flow->min_pack_size=new_flow->nbytes;
// 	new_flow->nbytes_sqr=new_flow->nbytes*new_flow->nbytes;

// 	new_flow->max_int_time=0;
// 	new_flow->min_int_time=0;
// 	new_flow->sum_int_time=0;
// 	new_flow->sum_int_time_sqr=0;

// 	int i,j;
// 	for(i=0;i<8;i++){
// 		if((new_flow->flags>>i)%2==1)
// 			new_flow->num_flags[i]=1;
// 		else
// 			new_flow->num_flags[i]=0;
// 	}

// 	new_flow->rtt_syn_done=0;
// 	if(((new_flow->flags>>1)%2)==1){//SYN
// 		new_flow->rtt_syn=last_packet_timestamp;
// 	}
// 	else{
// 		new_flow->rtt_syn=0;
// 		new_flow->rtt_syn_done=1;
// 	}
// 	uint8_t*aux=new_flow->payload_ptr;
// 	if(aux)
// 	{
// 		if (max_payload > new_flow->dataLen)
// 		{
// 			  //printf("new_flow->offset:%u,new_flow->dataLen:%u,%"PRIu64".%06lu,%u,%u,%u\n",new_flow->offset,new_flow->dataLen,last_packet_timestamp/1000000,last_packet_timestamp%1000000,new_flow->source_port,new_flow->destination_port,new_flow->transport_protocol);
		
// 			memcpy (new_flow->payload, aux, new_flow->dataLen * sizeof (uint8_t));
			 

// 		}
// 		else
// 		{
			 

// 			memcpy (new_flow->payload, aux, max_payload * sizeof (uint8_t));
			

// 		}
// 	}
// 	new_flow->npack_payload=1;

	
// 	aux_session->actual_flow=&(aux_session->incoming);
	
// //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// // Frag. packets
// //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// 	if (frag_packets_flag)
// 	{
// 		aux_session->actual_flow->frag_flag=1;
// 		aux_session->actual_flow->ip_id=new_flow->ip_id;
// 		insertPointer_frag(aux_session->actual_flow);
// 		frag_packets_flag=0;
// 	}

// 	else aux_session->actual_flow->frag_flag=0;

// 	getNodel();
// 	naux=nodel_aux;
// 	naux->data=(aux_session);
// 	list_prepend_node(&list,naux);
// 	session_table[index]=list;  //asignamos por si ha cambiado la cabeza

// 	getNodel();
// 	new_active_node=nodel_aux;
// 	new_active_node->data=naux;
// 	list_prepend_node(&active_session_list,new_active_node);
// 	aux_session->active_node=new_active_node;
	
// 	//actualizamos contadores de flujos concurrentes por subred/puertos
// /*	for(i=0;i<n_networks;i++){
// 		if((new_flow->source_ip&mask_networks[i])==networks[i])
// 			flows_networks_out[i]++;
// 		if((new_flow->destination_ip&mask_networks[i])==networks[i]){
// 			flows_networks_in[i]++;
// 		}
// 	}*/
//  	for(i=0;i<n_networks;i++)
// 	{
//                 if((aux_session->incoming.source_ip&mask_networks[i])==networks[i])
//                 {
// 			if(mac_in!=NULL)
// 			{
// 				if(((memcmp(&aux_session->incoming.source_mac,mac_in,ETH_ALEN)==0)))
// 		                {
// 					for(j=0;j<nmacs_out;j++)
// 					{
// 						if((memcmp(&aux_session->incoming.destination_mac,macs_out[j],ETH_ALEN)==0))
// 						{
// 							flows_networks_out[i]++;
// 							break;
// 						}
// 					}
	
// 		                }
// 			}
// 			else
// 				flows_networks_out[i]++;	
			
//                 }
//                 if((aux_session->incoming.destination_ip&mask_networks[i])==networks[i])
// 		{
// 			if(macs_out!=NULL)
// 			{
// 				for(j=0;j<nmacs_out;j++)
// 				{
// 					if((memcmp(&aux_session->incoming.source_mac,macs_out[j],ETH_ALEN)==0))
// 					{
// 						if(((memcmp(&aux_session->incoming.destination_mac,mac_in,ETH_ALEN)==0)))
// 						{
// 							 flows_networks_in[i]++;
// 							 break;
// 						}
// 					}
// 				}
				
// 			}
// 			else
// 			{
// 				 flows_networks_in[i]++;
// 			}

//                 }
// 	}

// 	for(i=0;i<n_ports;i++){
// 		if(new_flow->source_port==ports[i])
// 			flows_ports_src[i]++;
// 		if(new_flow->destination_port==ports[i])
// 			flows_ports_dst[i]++;
// 	}


// 	active_session_list_size++;
// 	total_sessions++;

// 	if((aux_session->actual_flow->flag_FIN)>1)
// 	{
// 		node_l *n=list_search(&flags_expired_session_list,aux_session->active_node,compareTupleFlowList);
// 		if(n==NULL)
// 		{				
// 			list_unlink(&active_session_list,aux_session->active_node);
// 			list_prepend_node(&flags_expired_session_list,aux_session->active_node);
// 		}
		
// 	}

// 	return NULL;
// }

// inline void updateFlowTable(IPSession *current_session,IPFlow *new_flow){

// 	int num_packets = current_session->actual_flow->npack;
// 	if(new_flow->nbytes>current_session->actual_flow->max_pack_size)
// 		current_session->actual_flow->max_pack_size=new_flow->nbytes;
// 	if(new_flow->nbytes<current_session->actual_flow->min_pack_size)
// 		current_session->actual_flow->min_pack_size=new_flow->nbytes;
// 	current_session->actual_flow->nbytes_sqr+=new_flow->nbytes*new_flow->nbytes;
// 	if(current_session->actual_flow->rtt_syn_done==0){
// 		current_session->actual_flow->rtt_syn=last_packet_timestamp-current_session->actual_flow->rtt_syn;
// 		current_session->actual_flow->rtt_syn_done=1;
// 	}

// 	if(current_session->actual_flow->npack==1){
// 	//if(current_session->actual_flow->max_int_time==0){//2nd packet
// 		current_session->actual_flow->max_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 		current_session->actual_flow->min_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 		current_session->actual_flow->sum_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 		current_session->actual_flow->sum_int_time_sqr=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp)*us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 	}
// 	else{//remaining packets
// 		if(current_session->actual_flow->max_int_time<us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp))
// 			current_session->actual_flow->max_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 		if(current_session->actual_flow->min_int_time>us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp))
// 			current_session->actual_flow->min_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 		current_session->actual_flow->sum_int_time+=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 		current_session->actual_flow->sum_int_time_sqr+=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp)*us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
// 	}	


// 	current_session->actual_flow->previous_timestamp=last_packet_timestamp;

// 	int i;
// 	for(i=0;i<8;i++){
// 		if((new_flow->flags>>i)%2==1)
// 			new_flow->num_flags[i]++;
// 	}

// 	uint16_t copySize=0;
// 	if(current_session->actual_flow->flag_FIN==0)
// 		(current_session->actual_flow->flag_FIN)+=(new_flow->flag_FIN);


// 	(current_session->actual_flow->nbytes) += new_flow->nbytes;
	
// 	current_session->actual_flow->previous_seq_number=new_flow->current_seq_number+new_flow->dataLen;


// 	if(new_flow->dataLen+current_session->actual_flow->offset<=max_payload)
// 		copySize=new_flow->dataLen;
// 	else if((int)(max_payload-current_session->actual_flow->offset)>0)
// 		copySize=max_payload-current_session->actual_flow->offset;
// 	else
// 		copySize=0;


// 	if (num_packets < max_pack)
// 	{
// 		(current_session->actual_flow->timestamp)[num_packets] =(last_packet_timestamp);
// 		(current_session->actual_flow->size)[num_packets] = (new_flow->nbytes);
// 		(current_session->actual_flow->packet_offset)[num_packets] =(copySize);
// 	}
// 	//Do not copy more than the max_payload 
// 	if (copySize > 0)
// 	{
// 		current_session->actual_flow->npack_payload++;
// 		uint8_t*aux=new_flow->payload_ptr;

// 		if(aux)
// 		{
// 			memcpy (current_session->actual_flow->payload + (current_session->actual_flow->offset),aux, copySize);
// 			(current_session->actual_flow->offset) += copySize;
		
// 		}
// 	}

// 	current_session->lastpacket_timestamp = last_packet_timestamp;
// 	(current_session->actual_flow->npack)++;

// //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// // Frag. packets
// //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// 	if (frag_packets_flag)
// 	{

// 		if (current_session->actual_flow->frag_flag==0)
// 		{
// 			current_session->actual_flow->frag_flag=1;
// 			current_session->actual_flow->ip_id=new_flow->ip_id;
// 			insertPointer_frag(current_session->actual_flow);
// 		}

// 		else if (current_session->actual_flow->ip_id!=new_flow->ip_id)
// 		{
// 			removePointer_frag(current_session->actual_flow);
// 			current_session->actual_flow->ip_id=new_flow->ip_id;
// 			insertPointer_frag(current_session->actual_flow);
// 		}

// 		frag_packets_flag=0;
// 	}


// 	if((current_session->actual_flow->flag_FIN)>1)
// 	{
// 		node_l *n=list_search(&flags_expired_session_list,current_session->active_node,compareTupleFlowList);
// 		if(n==NULL)
// 		{				
// 			list_unlink(&active_session_list,current_session->active_node);
// 			list_prepend_node(&flags_expired_session_list,current_session->active_node);
// 		}

// /****************************************************************************************/
// // Aditional second for flag expirated flows
// /****************************************************************************************/
// 		else
// 		{
// 			list_unlink(&flags_expired_session_list,current_session->active_node);
// 			list_prepend_node(&flags_expired_session_list,current_session->active_node);
// 		}
		
// 	}
// 	else
// 	{

// 		list_unlink(&active_session_list,current_session->active_node);
// 		list_prepend_node(&active_session_list,current_session->active_node);
// 	}
// }

//Add enough data to compare two hashvalues
void preFillHashvalue(packet_info *packet, hash_value *hashvalue){
   
	if(packet->request){
		hashvalue->ip_client_int = inet_addr(packet->ip_addr_src);
		hashvalue->ip_server_int = inet_addr(packet->ip_addr_dst);
		hashvalue->port_client   = packet->port_src;
		hashvalue->port_server   = packet->port_dst;
	}else{ //Si es respuesta la ip de origen es la del servidor
		hashvalue->ip_server_int = inet_addr(packet->ip_addr_src);
		hashvalue->ip_client_int = inet_addr(packet->ip_addr_dst);
		hashvalue->port_server   = packet->port_src;
		hashvalue->port_client   = packet->port_dst;
	}

	return;
}

int check_hash_err(node_l *list){
	node_l *n = list_get_first_node(&list);
	if(n!=NULL){
		if(n->data == NULL){
			list_unlink(&list, n);
			if(n->data == NULL){
				return 1;
			}

		}
	}else{
		return 0;
	}

	return 0;
}

//Completes the information of the hashvalue
void fulfillHashvalue(packet_info *packet, hash_value *hashvalue){

	strncpy(hashvalue->ip_client, packet->ip_addr_src, ADDR_CONST);
	strncpy(hashvalue->ip_server, packet->ip_addr_dst, ADDR_CONST);
	hashvalue->n_request     = 0;
	hashvalue->n_response    = 0;
	hashvalue->deleted_nodes = 0;
	hashvalue->ip_client_int = inet_addr(packet->ip_addr_src);
	hashvalue->ip_server_int = inet_addr(packet->ip_addr_dst);
	hashvalue->port_client   = packet->port_src;
	hashvalue->port_server   = packet->port_dst;

}

int compareHashvalue(void *a, void *b)
{

	if(a == NULL || b == NULL){
		return 1;
	}

	if(	(((hash_value*)a)->ip_client_int == ((hash_value*)b)->ip_client_int) &&
		(((hash_value*)a)->ip_server_int == ((hash_value*)b)->ip_server_int) &&
		(((hash_value*)a)->port_client == ((hash_value*)b)->port_client) &&
		(((hash_value*)a)->port_server == ((hash_value*)b)->port_server)
	)
	{
		return 0;
	}
	
	return 1;
}

/*******************************************************
*
* This function inserts/updates a session in the GLOBAL
* flows table. 
*
********************************************************/
int insertPacket (packet_info *aux_packet){

	node_l *new_active_node = NULL;

	//ACK & SEQ
	aux_packet->tcp->th_seq = ntohl(aux_packet->tcp->th_seq);
	aux_packet->tcp->th_ack = ntohl(aux_packet->tcp->th_ack);

	//Obtener hashkey
	uint32_t index = getIndex (aux_packet);

	//Obtener lista de colisiones
	node_l *list=session_table[index];

	preFillHashvalue(aux_packet, &aux_hashvalue);
	
	if(options.debug){
		fprintf(stderr, "DEBUG/ DATA: %s|%d|%s|%d|%ld.%09ld|SEQ:%"PRIu32"|ACK:%"PRIu32"|%s\n", aux_packet->ip_addr_src, aux_packet->port_src, aux_packet->ip_addr_dst, aux_packet->port_dst, aux_packet->ts.tv_sec, aux_packet->ts.tv_nsec, aux_packet->tcp->th_seq, aux_packet->tcp->th_ack, http_op_to_char(aux_packet->op));
	}

	if(options.debug){
		fprintf(stderr, "DEBUG/ preFillHashvalue - done\n");
	}
	
	list_alloc_node_no_malloc(&aux_hashvalue);
	
	if(options.debug){
		fprintf(stderr, "DEBUG/ list_alloc_node_no_malloc - done\n");
	}

	//Buscar conexion en colisiones
	node_l *conexion_node = list_search(&list, &static_node, compareHashvalue);

	if(options.debug){
		fprintf(stderr, "DEBUG/ search - done\n");
	}	

	node_l *naux = NULL;

	if(conexion_node == NULL){ //------------------ //La conexion no esta en la tabla, meter nueva

		if(check_hash_err(list)){
			list = NULL;
			// releaseNodel(list[index]);
		}

		if(options.debug){
			fprintf(stderr, "DEBUG/ new conexion\n");
		}
		if(!aux_packet->request){ 					//Response sin request
			if(options.debug){
				fprintf(stderr, "DEBUG/ Response without request\n");
			}
			return -1;
		}else{					 					//PRIMERA PETICION DE LA CONEXION
			hash_value *hashvalue = getHashvalue(); //Obtener hashvalue del pool
			if(options.debug){
				fprintf(stderr, "DEBUG/ get hashvalue from pool - done\n");
			}
			fulfillHashvalue(aux_packet, hashvalue);//Copiar datos
			if(options.debug){
				fprintf(stderr, "DEBUG/ fulfillHashvalue - done\n");
			}
			getNodel();								//Obtener nodo del pool
			if(options.debug){
				fprintf(stderr, "DEBUG/ get node from pool - done\n");
			}
			naux=nodel_aux;							//
			request *req = getRequest();			//Obtener request del pool
			if(options.debug){
				fprintf(stderr, "DEBUG/ get request from pool - done\n");
			}
			fillRequest(aux_packet, req);			//Rellenar request
			if(options.debug){
				fprintf(stderr, "DEBUG/ fillRequest - done\n");
			}
			naux->data = req;						 //Asignar request al nuevo nodo
			list_append_node(&hashvalue->list, naux);//Meter al final de la lista de transacciones
													 //de la conexion

			if(options.debug){
				fprintf(stderr, "DEBUG/ append request - done\n");
			}

			hashvalue->last_client_seq = aux_packet->tcp->th_seq; //Actualizar ultimos numeros
			hashvalue->last_client_ack = aux_packet->tcp->th_ack; //de seq y ack del cliente
			hashvalue->n_request++;
			hashvalue->last_ts = aux_packet->ts;				  //Actualizar last timestamp

			getNodel();											  //Obtener nodo del pool
			if(options.debug){
				fprintf(stderr, "DEBUG/ get node from pool - done\n");
			}
			naux=nodel_aux;										  //
			naux->data=hashvalue;								  //Asignar la conexion al nodo
			list_prepend_node(&list,naux);						  //Meter en lista de colisiones		
			if(options.debug){
				fprintf(stderr, "DEBUG/ prepend conexion - done\n");
			}

			session_table[index]=list;  						  //Actualizar lista de colisiones
																  //en la tabla hash
			
			getNodel();											  //Obtener nodo del pool
			new_active_node=nodel_aux;							  //Asignar conexion
			new_active_node->data=naux;							  
			list_prepend_node(&active_session_list, new_active_node); //Anadir al principio de la lista de activos
			hashvalue->active_node=new_active_node;
			active_session_list_size++;

			if(options.debug){
				fprintf(stderr, "DEBUG/ meter en tabla hash - done\n");
			}
		}
	}else{ //-------------------------------------- //La conexion existe
		hash_value *hashvalue = (hash_value*) conexion_node->data;
		hashvalue->last_ts = aux_packet->ts;		//Actualizar last timestamp
		if(options.debug){
			fprintf(stderr, "DEBUG/ Conexion exists\n");
		}
		//PETICION 

		if(aux_packet->request && 								 // La PETICION debe tener un SEQ
		(hashvalue->last_client_seq < aux_packet->tcp->th_seq)){ // mayor que el anterior
			getNodel();											 // Obtener nodo del pool
			if(options.debug){
				fprintf(stderr, "DEBUG/ REQUEST, getNodel - done\n");
			}
			naux=nodel_aux;							//
			request *req = getRequest();			//Obtener request del pool
			fillRequest(aux_packet, req);			//Rellenar request
			if(options.debug){
				fprintf(stderr, "DEBUG/ getRequest, fillRequest - done\n");
			}
			naux->data = req;										//Asignar request al nuevo nodo
			list_append_node(&hashvalue->list, naux); 				//Meter al final de la lista de transacciones
			if(options.debug){
				fprintf(stderr, "DEBUG/ append request - done\n");
			}
			session_table[index]=list;  							//Actualizar lista de colisiones

			hashvalue->last_client_seq = aux_packet->tcp->th_seq; 	//Actualizar ultimos numeros
			hashvalue->last_client_ack = aux_packet->tcp->th_ack; 	//de seq y ack del cliente
			hashvalue->n_request++;

			//UPDATE ACTIVE NODE LIST
			list_unlink(&active_session_list, hashvalue->active_node);
			list_prepend_node(&active_session_list, hashvalue->active_node);


		//RESPUESTA 
		}else if(!aux_packet->request && 						  	// La RESPUESTA debe tener un ACK
		(hashvalue->last_server_ack < aux_packet->tcp->th_ack)){  	// mayor que la anterior

			//BUSCAR NODO DONDE EL ACK DE LA PETICION == SEQ DE LA RESPUESTA

			if(options.debug){
				fprintf(stderr, "DEBUG/ RESPONSE\n");
			}
			
			node_l *req_node = request_search(&hashvalue->list, aux_packet->tcp->th_seq);
			if(req_node == NULL){
				if(options.debug){
					 fprintf(stderr, "NADA\n");
				}
				return -1;
			}
			
			request *req = (request*) req_node->data;
			// request *req = NULL;
			// if(hashvalue->list != NULL){
			// 	req = (request*) (hashvalue->list->data);
			// }else{
			// 	char *ts_res = NULL;
			// 	ts_res = timeval_to_char(aux_packet->ts);
			
			if(options.debug){
				fprintf(stderr, "DEBUG/ empty list: %s|%d|%s|%d|%ld.%09ld\n", hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server, aux_packet->ts.tv_sec, aux_packet->ts.tv_nsec);
			}

			// 	req = (request*) (hashvalue->list->data);
			// }

			// node_l *req_node = hashvalue->list;

			if(options.debug){
				fprintf(stderr, "DEBUG/ Get request - done\n");
			}

			//IMPRIMIR INFORMACION
			struct timespec diff = tsSubtract(aux_packet->ts, req->ts);
			fprintf(output, "%s|%i|%s|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%s|%d|%s|%s\n", hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server, req->ts.tv_sec, req->ts.tv_nsec, aux_packet->ts.tv_sec, aux_packet->ts.tv_nsec, diff.tv_sec, diff.tv_nsec, aux_packet->response_msg, aux_packet->responseCode, req->url, req->op == POST ? "POST" : "GET");
			if(options.debug){
				fprintf(stderr, "DEBUG/ PRINT INFO\n");
				fprintf(stderr, "DEBUG/ REQUEST: SEQ:%"PRIu32"|ACK:%"PRIu32"\n", req->seq, req->ack);
				fprintf(stderr, "DEBUG/ RESPONS: SEQ:%"PRIu32"|ACK:%"PRIu32"\n", aux_packet->tcp->th_seq, aux_packet->tcp->th_ack);
			}

			list_unlink(&hashvalue->list, req_node);					//Quitar nodo de la lista de transacciones
			if(options.debug){
				fprintf(stderr, "DEBUG/ unlink request - done\n");
			}
			req_node->data = NULL;										//Resetear data del nodo
			if(options.debug){
				fprintf(stderr, "DEBUG/ reset node - done\n");
			}
			releaseNodel(req_node);										//Devolver nodo al pool de nodos
			if(options.debug){
				fprintf(stderr, "DEBUG/ releaseNodel - done\n");
			}
			memset(req, 0, sizeof(request));							//Resetear request
			releaseRequest(req);										//Devolver request al pool de requests
			if(options.debug){
				fprintf(stderr, "DEBUG/ releaseRequest - done\n");
			}

			if(list_is_empty(&hashvalue->list)){ 						//Lista sin transacciones
				if(options.debug){
					fprintf(stderr, "DEBUG/ EMPTY LIST AFTER RESPONSE\n");
				}

				list_unlink(&list, conexion_node);						//Eliminar conexion
				conexion_node->data = NULL;
				releaseNodel(conexion_node);							//Devolver nodo al pool de nodos
				
				if(options.debug){
					fprintf(stderr, "DEBUG/ releaseNodel - done\n");
				}
				
				list_unlink(&active_session_list, hashvalue->active_node);//REMOVE NODE FROM ACTIVE NODE LIST
				active_session_list_size--;
				releaseNodel(hashvalue->active_node);
				hashvalue->active_node = NULL;

				memset(hashvalue, 0, sizeof(hashvalue));				//Resetear hashvalue
				releaseHashvalue(hashvalue);							//Devolver hashvalue al pool de hashvalues
				
				if(options.debug){
					fprintf(stderr, "DEBUG/ releaseHashvalue - done\n");
				}

				if(list_is_empty(&list)){ 								//Si la lista de colisiones esta vacia
					if(options.debug){
						fprintf(stderr, "DEBUG/ collision list empty\n");
					}
					session_table[index] = NULL;
				}

			}

			//Comprobar que la respuesta es a la primera peticion no satisfecha
			// if(req->ack != aux_packet->tcp->th_seq){
			// 	//IMPRIMIR INFORMACION DE LA TRANSACCION
			// 	//ELIMINAR LA PETICION DE LA LISTA DE TRANSACCIONES DE LA CONEXION
			// 	//ACTUALIZAR TABLA HASH
			// }else{ 
			// 	//buscar en las otras peticiones. Por si es la respuesta a una
			// 	//segunda peticion y la respuesta a la peticion anterior se ha perdido
			// 	//RECORRER LISTA HASTA QUE ACK == SEQ
			// }
			

			//Sino, buscar la peticion y usar el res_aux
			//Anadir ratio de responses a destiempo

		}else{ //Anadir mas casos 
			no_cases++;
			if(options.debug){
				fprintf(stderr, "DEBUG / NO CASE\n");
				fprintf(stderr, "DEBUG/ DATA2: %s|%d|%s|%d|%ld.%09ld|SEQ:%"PRIu32"|ACK:%"PRIu32"\n", aux_packet->ip_addr_src, aux_packet->port_src, aux_packet->ip_addr_dst, aux_packet->port_dst, aux_packet->ts.tv_sec, aux_packet->ts.tv_nsec, aux_packet->tcp->th_seq, aux_packet->tcp->th_ack);
				fprintf(stderr, "LAST CLIENT SEQ: %"PRIu32"\n", hashvalue->last_client_seq);
				fprintf(stderr, "LAST CLIENT ACK: %"PRIu32"\n", hashvalue->last_client_ack);
				fprintf(stderr, "LAST SERVER SEQ: %"PRIu32"\n", hashvalue->last_server_seq);
				fprintf(stderr, "LAST SERVER ACK: %"PRIu32"\n", hashvalue->last_server_ack);
			}
			return -1;
		}
	}

	return 0;
}

/*******************************************************
*
*  This function removes a flow from the list of active
*  flows and also from the table of individual flows. 
*
*  This function should be called after an export has been 
*  performed on the flow
*
********************************************************/
// IPSession * removeSession (node_l * current_node)
// {
// 	IPSession *current_session=NULL;
// 	node_l *current_node_session_table=NULL;
// 	uint32_t index=0;
	

// 	if (current_node == NULL)
// 		return NULL;

// 	current_node_session_table= (node_l*)(current_node->data);

// 	current_session=(IPSession*)(current_node_session_table->data);
// 	index=getIndex(&current_session->incoming);
// 	list_unlink(&(session_table[index]),current_node_session_table);
// 	list_unlink(&active_session_list,current_node);

// 	active_session_list_size--;
// 	//actualizamos contadores de flujos concurrentes por subred/puertos
// 	int i,j;
// 	for(i=0;i<n_networks;i++){
// 		if((current_session->incoming.source_ip&mask_networks[i])==networks[i])
// 		{
// 			if(macs_out!=NULL)
// 			{
// 				for(j=0;j<nmacs_out;j++)
// 				{
// 					if((memcmp(&current_session->incoming.destination_mac,macs_out[j],ETH_ALEN)==0))
// 				        {
// 				                if(((memcmp(&current_session->incoming.source_mac,mac_in,ETH_ALEN)==0)))
// 			       			 {	

// 							flows_networks_out[i]--;
// 							break;
// 						}
// 					}
// 				}
// 			}
// 			else
// 				flows_networks_out[i]--;
			
// 		}	
// 		if((current_session->incoming.destination_ip&mask_networks[i])==networks[i])
// 		{
// 			if(mac_in!=NULL)
// 			{
// 				if(((memcmp(&current_session->incoming.destination_mac,mac_in,ETH_ALEN)==0)))
//                                 {
// 					for(j=0;j<nmacs_out;j++)
// 					{
// 						if((memcmp(&current_session->incoming.source_mac,macs_out,ETH_ALEN)==0))
// 				        	{

// 								flows_networks_in[i]--;
// 								break;
// 						}
// 					}
// 				}
// 			}
// 			else
// 			{
// 				flows_networks_in[i]--;
// 			}
			
// 		}
// 	}
// 	for(i=0;i<n_ports;i++){
// 		if(current_session->incoming.source_port==ports[i])
// 			flows_ports_src[i]++;
// 		if(current_session->incoming.destination_port==ports[i])
// 			flows_ports_dst[i]++;
// 	}
// 	releaseNodel(current_node_session_table);
// 	releaseNodel(current_node);

// 	current_session->exportation_timestamp=last_packet_timestamp;

// // Frag. packets
// 	if (current_session->incoming.frag_flag) removePointer_frag(&(current_session->incoming));

// 	return current_session;
// }



/*******************************************************
*
*  This function calculates the index in the FLOWS table
*  from the source ip or the destination ip. 
*
********************************************************/
uint32_t getIndex(packet_info * packet){
	return (inet_addr(packet->ip_addr_src) + inet_addr(packet->ip_addr_dst) + packet->port_src + packet->port_dst)%MAX_FLOWS_TABLE_SIZE;
}

uint32_t getIndexFromHashvalue(hash_value *hashvalue){
	return (hashvalue->ip_client_int + hashvalue->ip_server_int + hashvalue->port_client + hashvalue->port_server)%MAX_FLOWS_TABLE_SIZE;
}

/*******************************************************
*
*  This function clean up the list of active flows 
*  (exporting and removing expired flows)
*
*
********************************************************/
// void cleanup_flows ()
// {

// 	node_l *n=NULL,*naux=NULL;
// 	node_l *current_node_session_table=NULL;
// 	IPSession *current_session=NULL;
	
// 	uint64_t aux = 0;
	
// 	n=list_get_last_node(&active_session_list);

// 	while(n != NULL) 
// 	{
		
// 		current_node_session_table=(node_l*)n->data;
// 		current_session=(IPSession*)current_node_session_table->data;
// 		aux =(last_packet_timestamp - ((current_session)->lastpacket_timestamp));


// 		if ((aux > expiration_flow_time))
// 		{
// 			naux=n;  
// 			n = list_get_prev_node(&active_session_list, n);
// 			if (export)
// 				export (removeSession (naux));
// 			else
// 				removeSession (naux);
// 		}
// 		else
// 			break;

// 	}

// //	n=flags_expired_session_list;
// 	n=list_get_last_node(&flags_expired_session_list); //MODIFIED

// 	while(n != NULL) 
// 	{	


// **************************************************************************************
// // Aditional second for flag expirated flows
// /****************************************************************************************/
// 		current_node_session_table=(node_l*)n->data;
// 		current_session=(IPSession*)current_node_session_table->data;
// 		aux =(last_packet_timestamp - ((current_session)->lastpacket_timestamp));


// 		if ((aux > expiration_flag_time))
// 		{

// /****************************************************************************************/
// /****************************************************************************************/
// 			naux=n; 
// 			n = list_get_prev_node(&flags_expired_session_list, n);
// 			if (export)
// 				export (removeSessionFlags (naux));
// 			else
// 				removeSessionFlags (naux);
// 		}

// 		else
// 			break;

// 	}
// }
