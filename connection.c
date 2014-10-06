#include "connection.h"

extern struct msgbuf sbuf;
//extern collision_list session_table[MAX_FLOWS_TABLE_SIZE]; //2^24 or 2^25
extern collision_list *session_table;
extern int resized_session_table;
extern node_l *active_session_list;
extern uint32_t active_session_list_size;
extern uint32_t max_active_session_list_size;
extern struct timespec last_packet;

extern FILE *output;

node_l static_node;

node_l *conn_pool_free=NULL;
node_l *conn_pool_used=NULL;

node_l *nodel_aux;

connection *conns;
connection aux_conn;

float pool_connections_used_ratio(){
    return list_size(&conn_pool_used) / ((float) MAX_POOL_FLOW);
}

void removeRequestFromConnection(connection *conn, node_l *req_node){

    request *req = (request*) req_node->data;
    list_unlink(&conn->list, req_node);
    req_node->data = NULL;                          //Resetear data del nodo
    releaseNodel(req_node);
        // memset(req, 0, sizeof(request));             //Resetear request
    req->aux_res = NULL;
    releaseRequest(req);                            //Devolver request al pool de requests
    conn->n_request--;
    decrement_active_requests();

    return;
}

void allocConnectionPool(void){
    
    size_t i=0;
    node_l *n=NULL;
    conns = calloc(MAX_POOL_FLOW, sizeof(connection));

    if(conns == NULL){
        fprintf(stderr, "Execute the program on a host with enought memory.\n");
    }

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
    {   fprintf(stderr, "pool conn vacío\n");
        exit(-1);
    }
    //Lo mete en el pool de usados
    list_prepend_node(&conn_pool_used,n);
    memset(n->data, 0, sizeof(connection)); //Resetear conn

    return  (n->data); //retorna el conn
    
}

void releaseConnection(connection * f)
{

    node_l *n=list_pop_first_node(&conn_pool_used);
    n->data=(void*)f;
    list_prepend_node(&conn_pool_free,n);

}

void alternativeFreeConnectionPool(void){
    node_l *n = NULL;

    conn_pool_free->prev->next = NULL;
    while(conn_pool_free != NULL && conn_pool_free->next !=NULL && conn_pool_free != conn_pool_free->next){
        n = conn_pool_free->next;
        FREE(conn_pool_free);
        conn_pool_free = n;
    }
    FREE(conn_pool_free);
    
    conn_pool_used->prev->next = NULL;
    while(conn_pool_used != NULL && conn_pool_used->next !=NULL && conn_pool_used != conn_pool_used->next){
        n = conn_pool_used->next;
        FREE(conn_pool_used);
        conn_pool_used = n;
    }
    FREE(conn_pool_used);

    FREE(conns);
}

void freeConnectionPool(void)
{
    node_l *n=NULL;
    while(conn_pool_free!=NULL)
    {
        n=list_pop_first_node(&conn_pool_free);
        FREE(n);
    }
    while(conn_pool_used!=NULL)
    {
        n=list_pop_first_node(&conn_pool_used);
        FREE(n);
    }
    FREE(conns);
}

//Add enough data to compare two conns
void preFillConnection(packet_info *packet, connection *conn){
   
    if(packet->request){
        conn->ip_client_int = packet->ip->ip_src.s_addr;
        conn->ip_server_int = packet->ip->ip_dst.s_addr;
        conn->port_client   = packet->port_src;
        conn->port_server   = packet->port_dst;
    }else{ //Si es respuesta la ip de origen es la del servidor
        conn->ip_server_int = packet->ip->ip_src.s_addr;
        conn->ip_client_int = packet->ip->ip_dst.s_addr;
        conn->port_server   = packet->port_src;
        conn->port_client   = packet->port_dst;
    }

    return;
}

//Completes the information of the conn
void fulfillConnection(packet_info *packet, connection *conn){

    // strncpy(conn->ip_client, packet->ip_addr_src, ADDR_CONST);
    // strncpy(conn->ip_server, packet->ip_addr_dst, ADDR_CONST);
    conn->n_request     = 0;
    conn->n_response    = 0;
    conn->deleted_nodes = 0;
    conn->ip_client_int = packet->ip->ip_src.s_addr;
    conn->ip_server_int = packet->ip->ip_dst.s_addr;
    conn->port_client   = packet->port_src;
    conn->port_server   = packet->port_dst;

}

int compareConnection(void *a, void *b)
{

    if(a == NULL || b == NULL){
        return 1;
    }

    if( (((connection*)a)->ip_client_int == ((connection*)b)->ip_client_int) &&
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

    // ERR_MSG("DEBUG/ addActiveConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromConnection(conn), conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);
    
    getNodel();                                       //Obtener nodo del pool
    node_l *naux=nodel_aux;                           //Asignar conexion
    naux->data=conn;
    list_prepend_node(&active_session_list, naux); //Anadir al principio de la lista de activos
    conn->active_node=naux;
    active_session_list_size++;
    if(active_session_list_size > max_active_session_list_size)
        max_active_session_list_size = active_session_list_size;

    return 0;
}

int removeActiveConnexion(connection *conn){

    // ERR_MSG("DEBUG/ removeActiveConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromConnection(conn), conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);

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

    increment_request_counter(aux_packet->op);

    node_l *naux = NULL;

    request *req = getRequest();                            //Obtener request del pool
    fillRequest(aux_packet, req);                           //Rellenar request
    getNodel();                                             //Obtener nodo del pool para la peticion
    naux = nodel_aux;
    naux->data = req;            
    list_append_node(&conn->list, naux);                //Meter peticion en la lista

    conn->last_client_seq = aux_packet->tcp->th_seq;    //Actualizar ultimos numeros
    conn->last_client_ack = aux_packet->tcp->th_ack;    //de seq y ack del cliente
    conn->n_request++;
    conn->last_ts = aux_packet->ts;                 //Actualizar last timestamp

    increment_active_requests();
    increment_total_requests();

}

void printRRD(struct timespec req_ts, struct timespec diff){
    static unsigned long second = 0;
    static unsigned long ctr = 0;
    static double df = 0;
    static int lines = 0;

    if(req_ts.tv_sec < second){
        return;
    }

    if(lines == 0){
        second = req_ts.tv_sec;
    }else if(req_ts.tv_sec > second){
        df = df / ((double) ctr);
        fprintf(output, "%ld %lf\n", second, df);
        second = req_ts.tv_sec;
        ctr = 0;
        df = 0;
    }

    df += diff.tv_sec;
    df += diff.tv_nsec * 0.000000001f;

    ctr++;
    lines++;

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

    if(options.sorted){
        addPrintElement(conn->ip_client_int, conn->ip_server_int, 
            conn->port_client, conn->port_server, req->ts, 
            res_ts, diff, responseCode, response_msg, req->host, req->url, req->op, req->seq);
    }else if(options.rrd){
        printRRD(req->ts, diff);
    }else if(!options.sorted){
        // if(options.index != NULL){
        //     fflush(output);
        //     write_to_index(ftell(output));
        // }
        //IPS TO PRETTY PRINT NUMBER VECTOR
        unsigned char ip_client[4] = {0};
        unsigned char ip_server[4] = {0};
        *(unsigned int *) ip_client = conn->ip_client_int;
        *(unsigned int *) ip_server = conn->ip_server_int;
        fprintf(output, "%d.%d.%d.%d|%i|%d.%d.%d.%d|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s|%s\n", 
            ip_client[0], ip_client[1], ip_client[2], ip_client[3], 
            conn->port_client, ip_server[0], ip_server[1], ip_server[2], ip_server[3], 
            conn->port_server, req->ts.tv_sec, req->ts.tv_nsec, res_ts.tv_sec, res_ts.tv_nsec, diff.tv_sec, diff.tv_nsec, 
            RESP_MSG_SIZE, response_msg, responseCode, http_op_to_char(req->op), req->host, req->url);        
    }

    conn->n_response--;
    removeRequestFromConnection(conn, req_node);
    
    increment_transactions();
}

void cleanUpConnection(connection *conn, FILE *gcoutput){

    node_l *n = list_get_first_node(&conn->list);
    if(n==NULL){
        return;
    }
    node_l *next = n->next;
    while(conn->n_request > 0 && n!= NULL){
        if(gcoutput != NULL){
            request *req = (request*) n->data;
            unsigned char ip_client[4] = {0};
            unsigned char ip_server[4] = {0};
            *(unsigned int *) ip_client = conn->ip_client_int;
            *(unsigned int *) ip_server = conn->ip_server_int;
            fprintf(gcoutput, "%d.%d.%d.%d|%i|%d.%d.%d.%d|%i|%ld.%09ld|%s|%s|%s\n", 
            ip_client[0], ip_client[1], ip_client[2], ip_client[3], conn->port_client,
            ip_server[0], ip_server[1], ip_server[2], ip_server[3], conn->port_server,
            req->ts.tv_sec, req->ts.tv_nsec, http_op_to_char(req->op), req->host, req->url);
        }
        removeRequestFromConnection(conn, n);
        n = next;
        if(n!=NULL){
            next = n->next;
        }

    }

}

void removeConnexion(connection *conn, node_l *conexion_node, uint32_t index){
    
    // ERR_MSG("DEBUG/ removeConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", index, conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);

    //ASSERT
    assert(!(conexion_node==NULL));//if(conexion_node==NULL) print_backtrace("removeConnexion conexion_node==NULL");

    removeActiveConnexion(conn);

    list_unlink(&session_table[index].list, conexion_node);          //Eliminar conexion    session_table[index].list = list;
    session_table[index].n--;
    // conexion_node->data = NULL;
    releaseNodel(conexion_node);

    //Devolver conn al pool
    //memset(conn, 0, sizeof(connection));   //Resetear conn
    //reset_connection(conn);
    releaseConnection(conn);                //Devolver conn al pool de conns

    if(session_table[index].n <= 0){
        session_table[index].list = NULL;
    }

}

int addResponseToConnexion(connection *conn, packet_info *aux_packet){

    // fprintf(stderr, "addResponseToConnexion %"PRIu32"\n", getIndex(aux_packet));

    int position = -1;
    node_l *req_node = request_search(conn->list, aux_packet->tcp->th_seq, &position);
    if(req_node == NULL){
        increment_total_req_node();
        return -1;
    }

    conn->n_response++;

    if(position==0){
        printTransaction(conn, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);   
    }else{
        printTransaction(conn, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);   
        increment_total_out_of_order();
    }

    conn->last_ts = aux_packet->ts;     //Actualizar last timestamp

    if(conn->n_request <= 0){
        return 1;
    }
    
    return 0;
}


int insertNewConnexion(packet_info *aux_packet, uint32_t index){

    node_l *naux = NULL;

    if(aux_packet->op == RESPONSE){         //Response sin request
        increment_total_responses();
        increment_lost();
        return -1;
    }

    //CREAR CONEXION
    connection *conn = getConnection();     //Obtener conn del pool
    fulfillConnection(aux_packet, conn);    //Copiar datos
    
    //METER PETICION
    addRequestToConnexion(conn, aux_packet);
    //OBTENER NODO PARA LA CONEXION
    getNodel();                             //Obtener nodo del pool
    naux=nodel_aux;                         //
    naux->data=conn;                        //Asignar la conexion al nodo


    list_append_node(&session_table[index].list, naux); //Meter en lista de colisiones        
    
    session_table[index].n++;
    
    // HASH TABLE INFO
    // if(session_table[index].n > session_table[index].max_n){
    //     session_table[index].max_n = session_table[index].n;
    // }

    increment_total_connexions();

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

    //ACK & SEQ
    
    // ERR_MSG("insertPacket\n");

    //Preparamos conn auxiliar y nodo auxiliar
    preFillConnection(aux_packet, &aux_conn);
    list_alloc_node_no_malloc(&aux_conn);

    uint32_t index = getIndex (aux_packet); //Obtener hashkey
    // ERR_MSG("insertPacket 1 %"PRIu32"\n", index);
    node_l *list = session_table[index].list;      //Obtener lista de colisiones
    // ERR_MSG("insertPacket 2\n");

    //Buscar conexion en colisiones
    node_l *conexion_node = list_search(list, &static_node, compareConnection);

    //La conexion no esta en la tabla, meter nueva
    if(conexion_node == NULL){
        return insertNewConnexion(aux_packet, index);
    }else{ //La conexion existe

        connection *conn = (connection*) conexion_node->data;
        if(conn == NULL){
            fprintf(stderr, "conn == NULL %"PRIu32"\n", index);
            list_unlink(&list, conexion_node);
            return insertNewConnexion(aux_packet, index);
        }
        
        //PETICION
        if(http_is_request(aux_packet->op)){
            addRequestToConnexion(conn, aux_packet);
            updateActiveConnexion(conn);
        //RESPUESTA
        }else if(aux_packet->op == RESPONSE){
            increment_total_responses();
            switch (addResponseToConnexion(conn, aux_packet)){
                case 0: //NORMAL CASE
                    updateActiveConnexion(conn);
                    break;
                case 1: //ERA LA ULTIMA PETICION EN LA LISTA
                    removeConnexion(conn, conexion_node, index);
                    break;
                default: //ERROR
                    return -1;
                    break;
            }

        //OTRO CASO NO ESPERADO
        }else{ //Anadir mas casos 
            increment_no_cases();
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
    if(packet->op == RESPONSE){
        return getIndex_global(packet->ip->ip_dst.s_addr, packet->ip->ip_src.s_addr, packet->port_dst, packet->port_src);
    }else{
        return getIndex_global(packet->ip->ip_src.s_addr, packet->ip->ip_dst.s_addr, packet->port_src, packet->port_dst); //OLD
    }
}

uint32_t getIndexFromConnection(connection *conn){
    return getIndex_global(conn->ip_client_int, conn->ip_server_int, conn->port_client, conn->port_server);
}



uint32_t getIndex_global(in_addr_t ip_a, in_addr_t ip_b, unsigned short port_a, unsigned short port_b){
    // long double p_a = ((long double) port_a) * 1.55f;
    // long double p_b = ((long double) port_b) * 1.65f;
    // long double ip_a_ = ((long double) ip_a) * 1.75f;
    // long double ip_b_ = ((long double) ip_b) * 1.85f;
    
    // return ((uint32_t) (ip_a_ + ip_b_ + p_a + p_b))%MAX_FLOWS_TABLE_SIZE;   
    
    //return (ip_a + ip_b + port_a + port_b)%MAX_FLOWS_TABLE_SIZE;
    return (ip_a ^ ip_b ^ port_a ^ port_b) % MAX_FLOWS_TABLE_SIZE;


    // return resized_session_table ? (ip_a ^ ip_b ^ port_a ^ port_b)%BIG_MAX_FLOWS_TABLE_SIZE : (ip_a ^ ip_b ^ port_a ^ port_b)%MAX_FLOWS_TABLE_SIZE;
}
