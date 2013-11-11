#include "connection.h"

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

node_l *conn_pool_free=NULL;
node_l *conn_pool_used=NULL;

node_l *nodel_aux;

connection *conns;
connection aux_conn;

void removeRequestFromConnection(connection *conn, node_l *req_node){

    request *req = (request*) req_node->data;
    list_unlink(&conn->list, req_node);
    req_node->data = NULL;                          //Resetear data del nodo
    releaseNodel(req_node);
        // memset(req, 0, sizeof(request));             //Resetear request
    req->aux_res = NULL;
    releaseRequest(req);                            //Devolver request al pool de requests
    conn->n_request--;
    active_requests--;

    return;
}

void allocHasvaluePool(void){
    
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

    ERR_MSG("DEBUG/ addActiveConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromConnection(conn), conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);
    
    getNodel();                                       //Obtener nodo del pool
    node_l *naux=nodel_aux;                           //Asignar conexion
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
    
    if(getIndex(aux_packet) == 60224551){
        fprintf(stderr, "DEBUG/ addRequestToConnexion %"PRIu32" %s:%d %s:%d\n", 
            getIndex(aux_packet),
            conn->ip_client, conn->port_server, 
            conn->ip_server, conn->port_server);
    }

    node_l *naux = NULL;

    request *req = getRequest();                            //Obtener request del pool
    fillRequest(aux_packet, req);                           //Rellenar request
    getNodel();                                             //Obtener nodo del pool para la peticion
    naux = nodel_aux;
    naux->data = req;
    naux->next = naux;
    naux->prev = naux;              
    list_append_node(&conn->list, naux);                //Meter peticion en la lista

    conn->last_client_seq = aux_packet->tcp->th_seq;    //Actualizar ultimos numeros
    conn->last_client_ack = aux_packet->tcp->th_ack;    //de seq y ack del cliente
    conn->n_request++;
    conn->last_ts = aux_packet->ts;                 //Actualizar last timestamp

    active_requests++;
    total_requests++;

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

    conn->n_response--;
    removeRequestFromConnection(conn, req_node);
}

int cleanUpConnection(connection *conn){

    ERR_MSG("DEBUG/ cleanUpConnection - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", getIndexFromConnection(conn), conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);

    if(conn->n_request <= 0){
        return 0;
    }

    node_l *n = list_get_first_node(&conn->list);

    if(n == NULL){
        return 0;
    }

    removeRequestFromConnection(conn, n);
    return cleanUpConnection(conn);
}

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

void removeConnexion(connection *conn, node_l *conexion_node, uint32_t index){
    
    ERR_MSG("DEBUG/ removeConnexion - %"PRIu32" - %"PRIu32"; %"PRIu32" - %s:%u %s:%u \n", index, conn->ip_client_int, conn->ip_server_int, conn->ip_client, conn->port_client, conn->ip_server, conn->port_server);

    //ASSERT
    assert(!(conexion_node==NULL));//if(conexion_node==NULL) print_backtrace("removeConnexion conexion_node==NULL");

//  ERR_MSG("NULL %s - %s\n", conexion_node->prev == NULL? "NULL" : "!NULL", conexion_node->prev == conexion_node? "YES" : "NO");
//  ERR_MSG("NULL %s - %s\n", conexion_node->next == NULL? "NULL" : "!NULL", conexion_node->next == conexion_node? "YES" : "NO");

    removeActiveConnexion(conn);

    node_l *list=session_table[index];
    list_unlink(&list, conexion_node);          //Eliminar conexion
    conexion_node->data = NULL;
    releaseNodel(conexion_node);

    //Devolver conn al pool
    // memset(conn, 0, sizeof(conn));   //Resetear conn
    releaseConnection(conn);                //Devolver conn al pool de conns

    if(list_size(&list) == 0){                  //Si la lista de colisiones esta vacia
        session_table[index] = NULL;
    }

}

int addResponseToConnexion(connection *conn, packet_info *aux_packet){

    int position = -1;
    node_l *req_node = request_search(&conn->list, aux_packet->tcp->th_seq, &position);
    if(req_node == NULL || req_node->data == NULL){
        total_req_node++;
        return -1;
    }

    conn->n_response++;

    if(position==0){
        printTransaction(conn, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);   
    }else{
        printTransaction(conn, aux_packet->ts, aux_packet->response_msg, aux_packet->responseCode, req_node);   
        total_out_of_order++;
    }

    conn->last_ts = aux_packet->ts;     //Actualizar last timestamp


    if(conn->n_request <= 0){
        return 1;
    }
    
    return 0;
}


int insertNewConnexion(packet_info *aux_packet, uint32_t index){

    node_l *naux = NULL;

    if(aux_packet->op == RESPONSE){                     //Response sin request
        lost++;
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
    naux->prev = naux;
    naux->next = naux;  


    list_append_node(&session_table[index], naux); //Meter en lista de colisiones        
    
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

    //ACK & SEQ
    aux_packet->tcp->th_seq = ntohl(aux_packet->tcp->th_seq);
    aux_packet->tcp->th_ack = ntohl(aux_packet->tcp->th_ack);
    
    //Preparamos conn auxiliar y nodo auxiliar
    preFillConnection(aux_packet, &aux_conn);
    list_alloc_node_no_malloc(&aux_conn);

    uint32_t index = getIndex (aux_packet); //Obtener hashkey
    node_l *list=session_table[index];      //Obtener lista de colisiones

    //Buscar conexion en colisiones
    node_l *conexion_node = list_search(&list, &static_node, compareConnection);

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
        if(aux_packet->op == GET || aux_packet->op == POST){
            addRequestToConnexion(conn, aux_packet);
            updateActiveConnexion(conn);

        //RESPUESTA
        }else if(aux_packet->op == RESPONSE){

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
            no_cases++;
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