#ifndef HEADER_LIST_POOL_H
#define HEADER_LIST_POOL_H

#include "connection.h"

typedef struct {
    int n;
    node_l *list;
} collision_list;

#define HEADER_LIST_POOL_SIZE 20000

void allocHeaderListPool(void);
collision_list * getHeaderList(void);
void releaseHeaderList(collision_list * f);
void freeHeaderListPool(void);

#endif  