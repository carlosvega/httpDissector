#ifndef _EVENT_POOL_H
#define _EVENT_POOL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dissector_structs.h"

#define HTTP_EVENT_POOL_SIZE 1000000

//TODO: ALLOW MULTIPLE POOLS

void free_http_event_pool();
void alloc_http_event_pool();
http_event** pop_http_event();
void push_http_event(http_event **element);


#endif 
