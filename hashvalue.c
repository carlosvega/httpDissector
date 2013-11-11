#include "connection.h"

extern hashvalue session_table[MAX_FLOWS_TABLE_SIZE];

connection aux_conn;
node_l static_node;

void addConnection(node_l *conn_node){
	connection *conn = (connection*) conn_node->data;
	assert(conn!=NULL);
	uint32_t index = getIndexFromConnection(conn);
	hashvalue *hv = &session_table[index];
	list_append_node(&hv->list, conn_node);
	hv->n_connections++;

}

void removeConnection(node_l *conn_node){
	
	assert(conn_node != NULL);

	connection *conn = (connection*) conn_node->data;

	assert(conn != NULL);

	removeActiveConnexion(conn);

	uint32_t index = getIndexFromConnection(conn);
	hashvalue *hv = &session_table[index];
	list_unlink(&hv->list, conn_node); 			//Eliminar conexion
	hv->n_connections--;

	conn_node->data = NULL;
	releaseNodel(conn_node);
	releaseConnection(conn);

}

int getNumberOfConnections(uint32_t index){
	hashvalue *hv = &session_table[index];
	return hv->n_connections;
}
 
node_l* getConnectionNode(packet_info *aux_packet){

	//ACK & SEQ
	aux_packet->tcp->th_seq = ntohl(aux_packet->tcp->th_seq);
	aux_packet->tcp->th_ack = ntohl(aux_packet->tcp->th_ack);

	preFillConnection(aux_packet, &aux_conn);
	list_alloc_node_no_malloc(&aux_conn);

	uint32_t index = getIndex(aux_packet);
	hashvalue *hv = &session_table[index];

	if(hv->n_connections == 0){
		return NULL;
	}else{
		return list_safe_search(&hv->list, &static_node, compareConnection, hv->n_connections);
	}
	
}








