#ifndef _response_H
#define _response_H

#include <string.h>
#include "list.h"
#include "tools.h"
#include "packet_info.h"

uint32_t getGottenResponses();
void allocResponsePool(void);
response * getResponse(void);
void releaseResponse(response * f);
void freeResponsePool(void);
node_l *response_search(node_l **list, tcp_seq seq, int *number);
void fillResponse(packet_info *packet, response *res);

#endif
