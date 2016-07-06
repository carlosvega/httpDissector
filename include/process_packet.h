#ifndef _PROCESS_PACKET_H
#define _PROCESS_PACKET_H

#include "args_parse.h"
#include "http.h"
#include "hash_table.h"
#include "http_event_pool.h"
#include "collision_list_pool.h"
#include "tools.h"
#include "counters.h"

#define SNAPLEN 65535
#define PROMISC 1
#define to_MS 1000 //specifies the read timeout in milliseconds.

int begin_process(struct args_parse *o, process_info *p);

#endif