#ifndef HASHVALUE_H
#define HASHVALUE_H

#include "list.h"
#include "request.h"
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

#define MAX_FLOWS_TABLE_SIZE 16777216
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
void removeRequestFromHashvalue(hash_value *hashvalue);
void cleanup_flows();
hash_value* getHashvalue(void);
void releaseHashvalue(hash_value* f);
void freeHashvaluePool(void);
void fulfillHashvalue(packet_info *packet, hash_value *hashvalue);
void preFillHashvalue(packet_info *packet, hash_value *hashvalue);

#endif 