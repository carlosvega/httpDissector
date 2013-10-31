#include "hashvalue.h"

extern struct msgbuf sbuf;
extern node_l *session_table[MAX_FLOWS_TABLE_SIZE];
extern node_l *active_session_list;
extern uint32_t active_session_list_size;
extern struct timespec last_packet;

extern uint64_t last_packet_timestamp;
extern unsigned long long no_cases;
extern unsigned long long active_requests;
extern unsigned long long total_requests;
extern unsigned long long total_connexions;
extern unsigned long long lost;
extern unsigned long long total_req_node;
extern unsigned long long total_out_of_order;

extern FILE *output;

node_l static_node;

node_l *hashvalue_pool_free=NULL;
node_l *hashvalue_pool_used=NULL;

node_l *nodel_aux;

hash_value *hashvalues;
hash_value aux_hashvalue;

void removeRequestFromHashvalue(hash_value *hashvalue, node_l *req_node){

	request *req = (request*) req_node->data;
	list_unlink(&hashvalue->list, req_node);
	req_node->data = NULL;							//Resetear data del nodo
	releaseNodel(req_node);
		// memset(req, 0, sizeof(request));				//Resetear request
	req->aux_res = NULL;
	releaseRequest(req);							//Devolver request al pool de requests
	hashvalue->n_request--;
	active_requests--;

	return;
}

void allocHasvaluePool(void){
	
	int i=0;
	node_l *n=NULL;
	hashvalues = calloc(MAX_POOL_FLOW, sizeof(hash_value));

	//ASSERT
	assert(!(hashvalues==NULL));//if(hashvalues==NULL) print_backtrace("AllocHashvaluePool hashvalues==NULL");

	for(i=0;i<MAX_POOL_FLOW;i++){
		n=list_alloc_node(hashvalues+i);
		list_prepend_node(&hashvalue_pool_free,n);
	}

}

hash_value * getHashvalue(void){

	//Obtiene nodo del pool con el hashvalue nuevo
	node_l *n=list_pop_first_node(&hashvalue_pool_free);

	if(hashvalue_pool_free==NULL)
	{	fprintf(stderr, "pool hashvalue vacío\n");
		exit(-1);
	}
	//Lo mete en el pool de usados
	list_prepend_node(&hashvalue_pool_used,n);
	memset(n->data, 0, sizeof(hash_value));	//Resetear hashvalue

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

int addActiveConnexion(hash_value *hashvalue){

	ERR_MSG("DEBUG/ addActiveConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromHashvalue(hashvalue), hashvalue->ip_client_int, hashvalue->ip_server_int, hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server);
	
	getNodel();										  //Obtener nodo del pool
	node_l *naux=nodel_aux;							  //Asignar conexion
	naux->data=hashvalue;
	naux->next = naux;
	naux->prev = naux;
	list_prepend_node(&active_session_list, naux); //Anadir al principio de la lista de activos
	hashvalue->active_node=naux;
	active_session_list_size++;

	return 0;
}

// int removeActiveConnexion(node_l *n){

// 	n->data = NULL;
// 	list_unlink(&active_session_list, n);
// 	releaseNodel(n);
// 	active_session_list_size--;

// 	return 0;
// }

int removeActiveConnexion(hash_value *hashvalue){

	ERR_MSG("DEBUG/ removeActiveConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromHashvalue(hashvalue), hashvalue->ip_client_int, hashvalue->ip_server_int, hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server);

	list_unlink(&active_session_list, hashvalue->active_node);
	releaseNodel(hashvalue->active_node);
	hashvalue->active_node = NULL;	

	active_session_list_size--;

	return 0;
}

int updateActiveConnexion(hash_value *hashvalue){
	//UPDATE ACTIVE NODE LIST
	if(hashvalue->active_node == NULL){
		addActiveConnexion(hashvalue);
		return 0;
	}
	
	list_unlink(&active_session_list, hashvalue->active_node);
	list_prepend_node(&active_session_list, hashvalue->active_node);
	
	return 0;
}

void addRequestToConnexion(hash_value *hashvalue, packet_info *aux_packet, uint32_t index){
	
	ERR_MSG("DEBUG/ addRequestToConnexion\n");

	node_l *naux = NULL;

	request *req = getRequest();							//Obtener request del pool
	fillRequest(aux_packet, req);							//Rellenar request
	getNodel(); 											//Obtener nodo del pool para la peticion
	naux = nodel_aux;
	naux->data = req;				
	list_append_node(&hashvalue->list, naux); 				//Meter peticion en la lista

	hashvalue->last_client_seq = aux_packet->tcp->th_seq; 	//Actualizar ultimos numeros
	hashvalue->last_client_ack = aux_packet->tcp->th_ack; 	//de seq y ack del cliente
	hashvalue->n_request++;
	hashvalue->last_ts = aux_packet->ts;					//Actualizar last timestamp

	active_requests++;
	total_requests++;
}

void printTransaction(hash_value *hashvalue, struct timespec res_ts, char* response_msg, short responseCode, node_l *req_node){

	assert(hashvalue!=NULL);
	assert(response_msg!=NULL);
	assert(req_node!=NULL);

	ERR_MSG("DEBUG/ printTransaction\n");

	request *req = (request*) req_node->data;

	assert(req!=NULL);

	//IMPRIMIR INFORMACION
	struct timespec diff = tsSubtract(res_ts, req->ts);
	
	fprintf(output, "%s|%i|%s|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s\n", hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server, req->ts.tv_sec, req->ts.tv_nsec, res_ts.tv_sec, res_ts.tv_nsec, diff.tv_sec, diff.tv_nsec, RESP_MSG_SIZE, response_msg, responseCode, req->url, req->op == POST ? "POST" : "GET");
	hashvalue->n_response--;
	removeRequestFromHashvalue(hashvalue, req_node);
}

int cleanUpHashvalue(hash_value *hashvalue){

 	ERR_MSG("DEBUG/ cleanUpHashvalue - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromHashvalue(hashvalue), hashvalue->ip_client_int, hashvalue->ip_server_int, hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server);

	if(hashvalue->n_request == 0){
		return 0;
	}

	node_l *n = list_get_first_node(&hashvalue->list);

	if(n == NULL){
		return 0;
	}

	// request *req = (request*) n->data;
	// if(req == NULL){
	removeRequestFromHashvalue(hashvalue, n);
	return cleanUpHashvalue(hashvalue);
	// }

	// if(req->aux_res != NULL && hashvalue->n_response > 0){
	// 	response *res = (response*) req->aux_res;
	// 	assert(res != NULL);
	// 	if(res->op != RESPONSE){
	// 		syslog (LOG_NOTICE, "res->op!=RESPONSE %"PRIu32"\n", getIndexFromHashvalue(hashvalue));
	// 	}
	// 	printTransaction(hashvalue, res->ts, res->response_msg, res->responseCode, n);
	// 	releaseResponse(res);
	// 	return cleanUpHashvalue(hashvalue);
	// }else if(req->aux_res == NULL){
	// 	removeRequestFromHashvalue(hashvalue, n);
	// 	return cleanUpHashvalue(hashvalue);
	// }else if(req->aux_res != NULL && hashvalue->n_response <= 0){
	// 	syslog (LOG_NOTICE, "req->aux_res != NULL && hashvalue->n_response <= 0\n");
	// 	removeRequestFromHashvalue(hashvalue, n);
	// 	return cleanUpHashvalue(hashvalue);
	// }

	// return 0;
}

int checkFirst(hash_value *hashvalue){
	ERR_MSG("DEBUG/ checkFirst\n");

	if(hashvalue->n_request <= 0){
		return -1;
	}

	node_l *n = list_get_first_node(&hashvalue->list);

	if(n==NULL){
		return -1;
	}

	request *req = (request*) n->data;

	if(req == NULL){
		removeRequestFromHashvalue(hashvalue, n);
		return checkFirst(hashvalue);
	}

	// if(req->aux_res != NULL && hashvalue->n_response > 0){
	// 	response *res = (response*) req->aux_res;
	// 	assert(res != NULL);
	// 	if(res->op != RESPONSE){
	// 		syslog (LOG_NOTICE, "res->op!=RESPONSE %"PRIu32"\n", getIndexFromHashvalue(hashvalue));
	// 	}
				
	// 	// fprintf(stderr, "res->responseCode %d (%p) ", res->responseCode, &res->responseCode);
	// 	// fprintf(stderr, "res->response_msg %d (%p) \n", res->response_msg, &res->response_msg);
	// 	printTransaction(hashvalue, res->ts, res->response_msg, res->responseCode, n);
	// 	// memset(res, 0, sizeof(res)); //Resetear response
	// 	releaseResponse(res);
	// 	return checkFirst(hashvalue);
	// }else if(req->aux_res == NULL){
	struct timespec diff = tsSubtract(last_packet, req->ts);
	if(diff.tv_sec > 60){
		removeRequestFromHashvalue(hashvalue, n);
		return checkFirst(hashvalue);
	}else{
		return 0;
	}
	// }

	// return 0;

}

void removeConnexion(hash_value *hashvalue, node_l *conexion_node, uint32_t index){
	
	ERR_MSG("DEBUG/ removeConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", index, hashvalue->ip_client_int, hashvalue->ip_server_int, hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server);

	//ASSERT
	assert(!(conexion_node==NULL));//if(conexion_node==NULL) print_backtrace("removeConnexion conexion_node==NULL");

//	ERR_MSG("NULL %s - %s\n", conexion_node->prev == NULL? "NULL" : "!NULL", conexion_node->prev == conexion_node? "YES" : "NO");
//	ERR_MSG("NULL %s - %s\n", conexion_node->next == NULL? "NULL" : "!NULL", conexion_node->next == conexion_node? "YES" : "NO");

	removeActiveConnexion(hashvalue);

	node_l *list=session_table[index];
	list_unlink(&list, conexion_node); 			//Eliminar conexion
	conexion_node->data = NULL;
	releaseNodel(conexion_node);

	//Devolver hashvalue al pool
	// memset(hashvalue, 0, sizeof(hashvalue));	//Resetear hashvalue
	releaseHashvalue(hashvalue);				//Devolver hashvalue al pool de hashvalues

	if(list_size(&list) == 0){ 					//Si la lista de colisiones esta vacia
		session_table[index] = NULL;
	}

}

int addResponseToConnexion(hash_value *hashvalue, packet_info *aux_packet, node_l *conexion_node, uint32_t index){

	ERR_MSG("DEBUG/ addResponseToConnexion\n");

	int position = -1;
	node_l *req_node = request_search(&hashvalue->list, aux_packet->tcp->th_seq, &position);
	if(req_node == NULL || req_node->data == NULL){
		ERR_MSG("DEBUG/ req_node %s\n", req_node == NULL ? "NULL" : "!NULL");
		total_req_node++;
		return -1;
	}

	hashvalue->n_response++;

	if(position==0){
		printTransaction(hashvalue, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);	
	}else{
		printTransaction(hashvalue, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);	
		ERR_MSG("RESPONSE OUT OF ORDER POS: %d\n", position);
		total_out_of_order++;
		// request *req = (request*) req_node->data;
		// response *res = getResponse();
		// fillResponse(aux_packet, res);
		// res->op = RESPONSE;
		// req->aux_res = res;
	}

	if(hashvalue->n_request <= 0){
		removeConnexion(hashvalue, conexion_node, index);
	}else{
		updateActiveConnexion(hashvalue);
	}

	// if(checkFirst(hashvalue) == -1){ //n_req == 0
	// 	removeConnexion(hashvalue, conexion_node, index);
	// }else{
	// 	updateActiveConnexion(hashvalue);
	// }

	return 0;
}


int insertNewConnexion(node_l *list, packet_info *aux_packet, uint32_t index){

	node_l *naux = NULL;

	if(aux_packet->op == RESPONSE){ 					//Response sin request
		ERR_MSG("DEBUG/ Response without request\n");
		lost++;
		return -1;
	}

	//CREAR CONEXION
	hash_value *hashvalue = getHashvalue(); 	//Obtener hashvalue del pool
	fulfillHashvalue(aux_packet, hashvalue);	//Copiar datos

	ERR_MSG("DEBUG/ insertNewConnexion - %"PRIu32" - %s:%u %s:%u \n", index, hashvalue->ip_client, hashvalue->port_client, hashvalue->ip_server, hashvalue->port_server);
	
	//METER PETICION
	addRequestToConnexion(hashvalue, aux_packet, index);
	ERR_MSG("after addRequestToConnexion\n");
	//OBTENER NODO PARA LA CONEXION
	getNodel();											  //Obtener nodo del pool
	naux=nodel_aux;										  //
	naux->data=hashvalue;								  //Asignar la conexion al nodo
	naux->prev = naux;
	naux->next = naux;	

	if(list_is_empty(&list)){
		ERR_MSG("list_is_empty\n");
		session_table[index]=naux;
	}else{
		ERR_MSG("list_append_node\n");
		list_append_node(&list, naux);					  //Meter en lista de colisiones		
	}
	total_connexions++;

	addActiveConnexion(hashvalue);

	return 0;
}


/*******************************************************
*
* This function inserts/updates a session in the GLOBAL
* flows table. 
*
********************************************************/
int insertPacket (packet_info *aux_packet){

	// node_l *new_active_node = NULL;

	//ACK & SEQ
	aux_packet->tcp->th_seq = ntohl(aux_packet->tcp->th_seq);
	aux_packet->tcp->th_ack = ntohl(aux_packet->tcp->th_ack);

	//Preparamos hashvalue auxiliar y nodo auxiliar
	preFillHashvalue(aux_packet, &aux_hashvalue);
	list_alloc_node_no_malloc(&aux_hashvalue);

	//Obtener hashkey
	uint32_t index = getIndex (aux_packet);

	//Obtener lista de colisiones
	node_l *list=session_table[index];

	//Lista de colisiones vacia y no hay conexion
	if(list == NULL){
		ERR_MSG("DEBUG/ insertNewConnexion list==NULL\n");
		return insertNewConnexion(list, aux_packet, index);
	}

	//Buscar conexion en colisiones
	node_l *conexion_node = list_search(&list, &static_node, compareHashvalue);

	//La conexion no esta en la tabla, meter nueva
	if(conexion_node == NULL){
		ERR_MSG("DEBUG/ insertNewConnexion connexion_node==NULL\n");
		return insertNewConnexion(list, aux_packet, index);
	
	}else{ //La conexion existe
		hash_value *hashvalue = (hash_value*) conexion_node->data;
		hashvalue->last_ts = aux_packet->ts;		//Actualizar last timestamp
		
		//PETICION
		if(aux_packet->op == GET || aux_packet->op == POST){
		//&& 								 	// La PETICION debe tener un SEQ
		//(hashvalue->last_client_seq < aux_packet->tcp->th_seq)){ 	// mayor que el anterior
			ERR_MSG("DEBUG/ addRequestToConnexion\n");
			addRequestToConnexion(hashvalue, aux_packet, index);
			// updateActiveConnexion(hashvalue);
		//RESPUESTA
		}else if(aux_packet->op == RESPONSE){
			// && 						  									// La RESPUESTA debe tener un ACK
			//(hashvalue->last_server_ack < aux_packet->tcp->th_ack)){  	// mayor que la anterior
			ERR_MSG("DEBUG/ addResponseToConnexion\n");
			return addResponseToConnexion(hashvalue, aux_packet, conexion_node, index);
		
		}else{ //Anadir mas casos 
			no_cases++;
			ERR_MSG("DEBUG/ NO CASE (%s)\n", http_op_to_char(aux_packet->op));
			return -1;
		}
	}

	return 0;
}



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
