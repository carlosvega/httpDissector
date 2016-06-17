#ifndef _COLLISION_POOL_H
#define _COLLISION_POOL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dissector_structs.h"

#define COLLISION_LIST_POOL_SIZE 2000000

//TODO: ALLOW MULTIPLE POOLS

unsigned long get_used_collision_list_elements();
void free_collision_list_pool();
void alloc_collision_list_pool();
collision_list* pop_collision_list();
void push_collision_list(collision_list *element);


#endif 
