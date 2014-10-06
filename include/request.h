#ifndef _request_H
#define _request_H

#include <string.h>
#include "list.h"
#include "packet_info.h"

float pool_requests_used_ratio();
unsigned long long getGottenRequests();
void allocRequestPool(void);
request * getRequest(void);
void releaseRequest(request * f);
void freeRequestPool(void);
node_l *request_search(node_l *first, tcp_seq seq, int *number);
void fillRequest(packet_info *packet, request *req);

void alternativeFreeRequestPool(void);

#endif
