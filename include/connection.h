#ifndef CONNECTION_H
#define CONNECTION_H
#include <syslog.h>
#include <assert.h>
#include "counters.h"
#include "index.h"
#include "sorted_print.h"
#include "http.h"
#include "list.h"
#include "request.h"
#include "response.h"
#include "tools.h"
#include "packet_info.h"
#include "args_parse.h"


//---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <math.h>
#include <arpa/inet.h>

extern struct args_parse options;

#define ERR_MSG(...) do{if(options.debug){fprintf(stderr, __VA_ARGS__);}}while(0)
//#define ERR_MSG(...) do{if(options.debug){syslog (LOG_DEBUG, __VA_ARGS__);}}while(0)
#define MAX_FLOWS_TABLE_SIZE 16777216
#define BIG_MAX_FLOWS_TABLE_SIZE 1073741824
//4294967294
//16777216 2^24 33554432 2^25 67108864 2^26 134217728 2^27

typedef struct {
    int n;
    int max_n; //HASH TABLE INFO
    node_l *list;
} collision_list;

typedef struct {
    node_l *list;
    int n_request;
    int n_response;
    int deleted_nodes;
    char ip_client[ADDR_CONST];
	char ip_server[ADDR_CONST];
    in_addr_t ip_client_int;
    in_addr_t ip_server_int;
    unsigned short port_client;
    unsigned short port_server;
    tcp_seq last_client_seq;
    tcp_seq last_client_ack;
    tcp_seq last_server_seq;
    tcp_seq last_server_ack;
    struct timespec last_ts;
    node_l *active_node;
} connection;

float pool_connections_used_ratio();

uint32_t getIndex_global(in_addr_t ip_a, in_addr_t ip_b, unsigned short port_a, unsigned short port_b);
uint32_t getIndex(packet_info* packet);
uint32_t getIndexFromConnection(connection *conn);
void allocConnectionPool(void);
int insertPacket (packet_info *aux_packet);
void removeRequestFromConnection(connection *conn, node_l *req_node);
connection* getConnection(void);
void releaseConnection(connection* f);
void freeConnectionPool(void);
void fulfillConnection(packet_info *packet, connection *conn);
void preFillConnection(packet_info *packet, connection *conn);
int compareConnection(void *a, void *b);

void cleanUpConnection(connection *conn, FILE *gcoutput);
int addActiveConnexion(connection *conn);
int removeActiveConnexion(connection *conn);
int updateActiveConnexion(connection *conn);
void addRequestToConnexion(connection *conn, packet_info *aux_packet);
void printTransaction(connection *conn, struct timespec res_ts, char* response_msg, short responseCode, node_l *req_node);
void removeConnexion(connection *conn, node_l *conexion_node, uint32_t index);
int addResponseToConnexion(connection *conn, packet_info *aux_packet);
int insertNewConnexion(packet_info *aux_packet, uint32_t index);

#endif 
