#ifndef _tslist
#define _tslist

#include <time.h>
#include "util.h"

typedef struct _pair {
	struct _pair *next;
	packet_info *request;
	packet_info *response;
}pair;

typedef struct {
    pair *list;
    pair *last;
    int n_request;
    int n_response;
    int deleted_nodes;
    struct timespec last_ts;
} hash_value;

void init_list(hash_value *hashvalue);
void free_tslist(hash_value *list);
int remove_first_node(hash_value *hashvalue);
void add_tsnode_get(hash_value *list, packet_info *pkt);
void add_tsnode_res(hash_value *list, packet_info *pkt);

#endif
