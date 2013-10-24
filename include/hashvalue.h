#ifndef HASHVALUE_H
#define HASHVALUE_H
#include<syslog.h>
#include <assert.h>
#include "err_mqueue.h"
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
#define MAX_FLOWS_TABLE_SIZE 134217728
//16777216 2^24 134217728 2^27

typedef struct {
    node_l *list;
    node_l *active_node;
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
} hash_value;

uint32_t getIndex(packet_info* packet);
uint32_t getIndexFromHashvalue(hash_value *hashvalue);
void allocHasvaluePool(void);
int insertPacket (packet_info *aux_packet);
void removeRequestFromHashvalue(hash_value *hashvalue, node_l *req_node);
void cleanup_flows();
hash_value* getHashvalue(void);
void releaseHashvalue(hash_value* f);
void freeHashvaluePool(void);
void fulfillHashvalue(packet_info *packet, hash_value *hashvalue);
void preFillHashvalue(packet_info *packet, hash_value *hashvalue);
int compareHashvalue(void *a, void *b);
int check_dead_requests(hash_value *hashvalue);

int cleanUpHashvalue(hash_value *hashvalue);
int checkNextResponses(hash_value *hashvalue);
int addActiveConnexion(hash_value *hashvalue);
int removeActiveConnexion(hash_value *hashvalue);
int updateActiveConnexion(hash_value *hashvalue);
void addRequestToConnexion(hash_value *hashvalue, packet_info *aux_packet, uint32_t index);
void printTransaction(hash_value *hashvalue, struct timespec res_ts, char* response_msg, short responseCode, node_l *req_node);
void removeConnexion(hash_value *hashvalue, node_l *conexion_node, uint32_t index);
int addResponseToConnexion(hash_value *hashvalue, packet_info *aux_packet, node_l *conexion_node, uint32_t index);
int insertNewConnexion(node_l *list, packet_info *aux_packet, uint32_t index);

#endif 
