#ifndef _HASH_TABLE_H
#define _HASH_TABLE_H


//TABLA HASH
#include "http_event_pool.h"
#include "collision_list_pool.h"
#include "http.h"

void free_event_table();
void alloc_event_table();
int remove_event_from_table(hash_key *key);
http_event* get_event_from_table(hash_key *key);
http_event* create_collision_on_table(hash_key *key);



#endif