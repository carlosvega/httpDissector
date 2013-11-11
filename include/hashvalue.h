#ifndef HASHVALUE_H
#define HASHVALUE_H

typedef struct
{
	int n_connections;
	node_l *list;
}hashvalue;

void addConnection(node_l *conn_node);
void removeConnection(node_l *conn_node);
int getNumberOfConnections(uint32_t index);
node_l* getConnectionNode(packet_info *aux_packet);

#endif 