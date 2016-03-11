#ifndef _HASH_TABLE_H
#define _HASH_TABLE_H


//TABLA HASH
#include "http_event_pool.h"

/*
2^24    16,777,216
2^25    33,554,432
2^26    67,108,864
2^27   134,217,728
2^28   268,435,456
2^29   536,870,912
2^30 1,073,741,824
*/

#define EVENT_TABLE_SIZE 134217728 //2^24
#define COLLISION_SIZE 5//134217728/EVENT_TABLE_SIZE //2^27 / 2^25 = 4 

void free_event_table();
void alloc_event_table();
int remove_event_from_table(hash_key *key);
http_event** get_event_from_table(hash_key *key);



#endif