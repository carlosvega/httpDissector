#include "connection.h"

extern struct msgbuf sbuf;
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

node_l *conn_pool_free=NULL;
node_l *conn_pool_used=NULL;

node_l *nodel_aux;

connection *conns;
connection aux_conn;

void removeRequestFromConnection(connection *conn, node_l *req_node){

	request *req = (request*) req_node->data;
	//list_unlink(&conn->list, req_node);
	//UNLINK
	if(req_node->next == req_node){
		conn->list = NULL;
	}else{
		if(conn->list == req_node){
			conn->list = req_node->next;
		}

		req_node->prev->next = req_node->next;
		req_node->next->prev = req_node->prev;
	}

	req_node->next = req_node;
	req_node->prev = req_node;
	//END UNLINK

	req_node->data = NULL;							//Resetear data del nodo
	releaseNodel(req_node);
		// memset(req, 0, sizeof(request));				//Resetear request
	req->aux_res = NULL;
	releaseRequest(req);							//Devolver request al pool de requests
	conn->n_request--;
	active_requests--;

	if(conn->n_request == 0){
		conn->list = NULL;
	}

	return;
}

void allocConnectionPool(void){
	
	int i=0;
	node_l *n=NULL;
	conns = calloc(MAX_POOL_FLOW, sizeof(connection));

	//ASSERT
	assert(!(conns==NULL));//if(conns==NULL) print_backtrace("AllocConnectionPool conns==NULL");

	for(i=0;i<MAX_POOL_FLOW;i++){
		n=list_alloc_node(conns+i);
		list_prepend_node(&conn_pool_free,n);
	}

}

connection * getConnection(void){

	//Obtiene nodo del pool con el conn nuevo
	node_l *n=list_pop_first_node(&conn_pool_free);

	if(conn_pool_free==NULL)
	{	fprintf(stderr, "pool conn vacío\n");
		exit(-1);
	}
	//Lo mete en el pool de usados
	list_prepend_node(&conn_pool_used,n);
	memset(n->data, 0, sizeof(connection));	//Resetear conn

	return  (n->data); //retorna el conn
	
}

void releaseConnection(connection * f)
{

	node_l *n=list_pop_first_node(&conn_pool_used);
	n->data=(void*)f;
	list_prepend_node(&conn_pool_free,n);

}

void freeConnectionPool(void)
{
	node_l *n=NULL;
	while(conn_pool_free!=NULL)
	{
		n=list_pop_first_node(&conn_pool_free);
		free(n);
	}

	while(conn_pool_used!=NULL)
	{
		n=list_pop_first_node(&conn_pool_used);
		free(n);
	}
	free(conns);
}

//Add enough data to compare two conns
void preFillConnection(packet_info *packet, connection *conn){
   
	if(packet->request){
		conn->ip_client_int = inet_addr(packet->ip_addr_src);
		conn->ip_server_int = inet_addr(packet->ip_addr_dst);
		conn->port_client   = packet->port_src;
		conn->port_server   = packet->port_dst;
	}else{ //Si es respuesta la ip de origen es la del servidor
		conn->ip_server_int = inet_addr(packet->ip_addr_src);
		conn->ip_client_int = inet_addr(packet->ip_addr_dst);
		conn->port_server   = packet->port_src;
		conn->port_client   = packet->port_dst;
	}

	return;
}

//Completes the information of the conn
void fulfillConnection(packet_info *packet, connection *conn){

	strncpy(conn->ip_client, packet->ip_addr_src, ADDR_CONST);
	strncpy(conn->ip_server, packet->ip_addr_dst, ADDR_CONST);
	conn->n_request     = 0;
	conn->n_response    = 0;
	conn->deleted_nodes = 0;
	conn->ip_client_int = inet_addr(packet->ip_addr_src);
	conn->ip_server_int = inet_addr(packet->ip_addr_dst);
	conn->port_client   = packet->port_src;
	conn->port_server   = packet->port_dst;
	conn->list 			= NULL;

}

int compareConnection(void *a, void *b)
{

	if(a == NULL || b == NULL){
		return 1;
	}

	if(	(((connection*)a)->ip_client_int == ((connection*)b)->ip_client_int) &&
		(((connection*)a)->ip_server_int == ((connection*)b)->ip_server_int) &&
		(((connection*)a)->port_client == ((connection*)b)->port_client) &&
		(((connection*)a)->port_server == ((connection*)b)->port_server)
	)
	{
		return 0;
	}
	
	return 1;
}

int addActiveConnexion(connection *conn){

	ERR_MSG("DEBUG/ addActiveConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromConnection(conn), conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);
	
	getNodel();										  //Obtener nodo del pool
	node_l *naux=nodel_aux;							  //Asignar conexion
	naux->data=conn;
	naux->next = naux;
	naux->prev = naux;
	list_prepend_node(&active_session_list, naux); //Anadir al principio de la lista de activos
	conn->active_node=naux;
	active_session_list_size++;

	return 0;
}

int removeActiveConnexion(connection *conn){

	ERR_MSG("DEBUG/ removeActiveConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromConnection(conn), conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);

	list_unlink(&active_session_list, conn->active_node);
	releaseNodel(conn->active_node);
	conn->active_node = NULL;	

	active_session_list_size--;

	return 0;
}

int updateActiveConnexion(connection *conn){
	//UPDATE ACTIVE NODE LIST
	if(conn->active_node == NULL){
		addActiveConnexion(conn);
		return 0;
	}
	
	list_unlink(&active_session_list, conn->active_node);
	list_prepend_node(&active_session_list, conn->active_node);
	
	return 0;
}

void addRequestToConnexion(connection *conn, packet_info *aux_packet){
	
	ERR_MSG("DEBUG/ addRequestToConnexion\n");

	node_l *naux = NULL;

	request *req = getRequest();							//Obtener request del pool
	fillRequest(aux_packet, req);							//Rellenar request
	getNodel(); 											//Obtener nodo del pool para la peticion
	naux = nodel_aux;
	naux->data = req;
	naux->next = naux;
	naux->prev = naux;				
	list_append_node(&conn->list, naux); 				//Meter peticion en la lista

	conn->last_client_seq = aux_packet->tcp->th_seq; 	//Actualizar ultimos numeros
	conn->last_client_ack = aux_packet->tcp->th_ack; 	//de seq y ack del cliente
	conn->n_request++;
	conn->last_ts = aux_packet->ts;					//Actualizar last timestamp

	active_requests++;
	total_requests++;

	//CHECK IF LAST_CLIENT_SEQ == NEW SEQ
	//CHECK IF LAST_CLIENT_ACK == NEW ACK

	// fprintf(stderr, "addRequestToConnexion %"PRIu32" - %d, %d, seq:%"PRIu32", ack:%"PRIu32"\n", 
	// 	getIndexFromConnection(conn),
	// 	conn->n_request,
	// 	conn->n_response,
	// 	aux_packet->tcp->th_seq,
	// 	aux_packet->tcp->th_seq
	// );

}

void printTransaction(connection *conn, struct timespec res_ts, char* response_msg, short responseCode, node_l *req_node){

	assert(conn!=NULL);
	assert(response_msg!=NULL);
	assert(req_node!=NULL);

	ERR_MSG("DEBUG/ printTransaction\n");

	request *req = (request*) req_node->data;

	assert(req!=NULL);

	//IMPRIMIR INFORMACION
	struct timespec diff = tsSubtract(res_ts, req->ts);
	
	if(options.sorted == 0){
		fprintf(output, "%s|%i|%s|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s\n", conn->ip_client, conn->port_client, conn->ip_server, conn->port_server, req->ts.tv_sec, req->ts.tv_nsec, res_ts.tv_sec, res_ts.tv_nsec, diff.tv_sec, diff.tv_nsec, RESP_MSG_SIZE, response_msg, responseCode, req->url, req->op == POST ? "POST" : "GET");
	}else{
		addPrintElement(conn->ip_client, conn->ip_server, 
			conn->port_client, conn->port_server, req->ts, 
			res_ts, diff, responseCode, response_msg, req->url, req->op);
	}

	// if(conn->n_request > 1){
	// 	request *req_aux = (request*) conn->list->next->data;
	// 	fprintf(stderr, "req_aux: %s\n", req_aux == NULL? "NULL" : "!NULL");
	// }

	removeRequestFromConnection(conn, req_node);

	conn->n_response--;
	conn->deleted_nodes++;

	// fprintf(stderr, "PRINTED %"PRIu32" - %d, %d\n", 
	// 	getIndexFromConnection(conn),
	// 	conn->n_request,
	// 	conn->n_response
	// );

	// if(conn->n_request != 0){
	// 	if(conn->list != NULL){
	// 		request *req_aux = (request*) conn->list->data;
	// 		fprintf(stderr, "req_aux: %s\n", req_aux == NULL? "NULL" : "!NULL");
	// 	}
	// }

}

void cleanUpConnection(connection *conn){

	node_l *n = n = conn->list;

	while(conn->n_request > 0){
		
		if(n == NULL){
			break;
		}

		if(n->data!=NULL){
			request *req = (request*) n->data;
			releaseRequest(req);
		}
		
		list_unlink(&conn->list, n);
		releaseNodel(n);
		conn->n_request--;
		active_requests--;

		n=n->next;

	}

	conn->list = NULL;

}

// int cleanUpConnection(connection *conn){

//  	ERR_MSG("DEBUG/ cleanUpConnection - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromConnection(conn), conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);

// 	if(conn->n_request <= 0){
// 		return 0;
// 	}

// 	node_l *n = list_get_first_node(&conn->list);

// 	if(n == NULL){
// 		return 0;
// 	}

// 	removeRequestFromConnection(conn, n);
// 	return cleanUpConnection(conn);
// }

int checkFirst(connection *conn){
	ERR_MSG("DEBUG/ checkFirst\n");

	if(conn->n_request <= 0){
		return -1;
	}

	node_l *n = list_get_first_node(&conn->list);

	if(n==NULL){
		return -1;
	}

	request *req = (request*) n->data;

	if(req == NULL){
		removeRequestFromConnection(conn, n);
		return checkFirst(conn);
	}

	struct timespec diff = tsSubtract(last_packet, req->ts);
	if(diff.tv_sec > 60){
		removeRequestFromConnection(conn, n);
		return checkFirst(conn);
	}else{
		return 0;
	}

}

// void removeConnexion(connection *conn, node_l *conexion_node, uint32_t index){
	
// 	ERR_MSG("DEBUG/ removeConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", index, conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);

// 	//ASSERT
// 	assert(!(conexion_node==NULL));//if(conexion_node==NULL) print_backtrace("removeConnexion conexion_node==NULL");

// //	ERR_MSG("NULL %s - %s\n", conexion_node->prev == NULL? "NULL" : "!NULL", conexion_node->prev == conexion_node? "YES" : "NO");
// //	ERR_MSG("NULL %s - %s\n", conexion_node->next == NULL? "NULL" : "!NULL", conexion_node->next == conexion_node? "YES" : "NO");

// 	removeActiveConnexion(conn);

// 	node_l *list=session_table[index];
// 	list_unlink(&list, conexion_node); 			//Eliminar conexion
// 	conexion_node->data = NULL;
// 	releaseNodel(conexion_node);

// 	//Devolver conn al pool
// 	// memset(conn, 0, sizeof(conn));	//Resetear conn
// 	releaseConnection(conn);				//Devolver conn al pool de conns

// 	if(list_size(&list) == 0){ 					//Si la lista de colisiones esta vacia
// 		session_table[index] = NULL;
// 	}

// }

int addResponseToConnexion(connection *conn, packet_info *aux_packet){

	ERR_MSG("DEBUG/ addResponseToConnexion\n");

	int position = -1;
	// fprintf(stderr, "NC: %d\tNR: %d\tNr: %d\tDN: %d %"PRIu32"\n", 
	// 	getNumberOfConnections(getIndex(aux_packet)),
	// 	conn->n_request,
	// 	conn->n_response,
	// 	conn->deleted_nodes,
	// 	getIndex(aux_packet)
	// );
	node_l *req_node = request_search(&conn->list, aux_packet->tcp->th_seq, &position, conn->n_request);
	if(req_node == NULL || req_node->data == NULL){
		ERR_MSG("DEBUG/ req_node %s\n", req_node == NULL ? "NULL" : "!NULL");
		total_req_node++;
		return -1;
	}

	conn->n_response++;
	conn->last_ts = aux_packet->ts;		//Actualizar last timestamp

	// fprintf(stderr, "position: %d\n", position);

	if(position==0){
		printTransaction(conn, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);	
	}else{
		printTransaction(conn, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);	
		ERR_MSG("RESPONSE OUT OF ORDER POS: %d\n", position);
		total_out_of_order++;
	}

	return 0;
}


int insertNewConnexion(packet_info *aux_packet){

	node_l *naux = NULL;

	if(aux_packet->op == RESPONSE){ 					//Response sin request
		ERR_MSG("DEBUG/ Response without request\n");
		lost++;
		return -1;
	}

	//CREAR CONEXION
	connection *conn = getConnection(); 	//Obtener conn del pool
	fulfillConnection(aux_packet, conn);	//Copiar datos
	
	//METER PETICION
	addRequestToConnexion(conn, aux_packet);

	ERR_MSG("after addRequestToConnexion\n");
	//OBTENER NODO PARA LA CONEXION
	getNodel();											  //Obtener nodo del pool
	naux=nodel_aux;										  //
	naux->data=conn;								  //Asignar la conexion al nodo
	naux->prev = naux;
	naux->next = naux;	

	addConnection(naux);

	total_connexions++;

	addActiveConnexion(conn);

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
	
	node_l* conn_node = getConnectionNode(aux_packet);

	//La conexion no esta en la tabla
	if(conn_node == NULL){
		return insertNewConnexion(aux_packet);
	}else{ //La conexion existe
		connection *conn = (connection*) conn_node->data;
		assert(conn!=NULL);
		// if(conn == NULL){ //No deberia pasar
		// 	fprintf(stderr, "conn == NULL\n");
		// 	list_unlink(&list, conexion_node);
		// 	return insertNewConnexion(aux_packet);
		// }
		
		//PETICION
		if(aux_packet->op == GET || aux_packet->op == POST){
			addRequestToConnexion(conn, aux_packet);
			updateActiveConnexion(conn);
		//RESPUESTA
		}else if(aux_packet->op == RESPONSE){
			if(addResponseToConnexion(conn, aux_packet) == -1){
				return -1;
			}else{
				if(conn->n_request <= 0){
					removeConnection(conn_node);
				}else{
					updateActiveConnexion(conn);
				}
			}
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

uint32_t getIndexFromConnection(connection *conn){
	return (conn->ip_client_int + conn->ip_server_int + conn->port_client + conn->port_server)%MAX_FLOWS_TABLE_SIZE;
}
