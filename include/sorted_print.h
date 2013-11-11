#ifndef _sorted_print_H
#define _sorted_print_H

#include <string.h>
#include "list.h"
#include "tools.h"
#include "http.h"

#define PRINT_POOL_SIZE 1

typedef struct {
  //IPs and ports
  char ip_client[ADDR_CONST];
  char ip_server[ADDR_CONST];
  unsigned short port_client;
  unsigned short port_server;
  //Timestamps
  struct timespec req_ts;
  struct timespec res_ts;
  struct timespec diff;
  //
  short responseCode;
  char  response_msg[RESP_MSG_SIZE];
  char  url[URL_SIZE];
  http_op op;
} print_element;

print_element print_element_list[PRINT_POOL_SIZE];

void addPrintElement(char *ip_client, char *ip_server,
 unsigned short port_client, unsigned short port_server,
 struct timespec req_ts, struct timespec res_ts, struct timespec diff,
 short responseCode, char *response_msg, char *url, http_op op);

void sortPrintElements();
void printElements();
int sortedPrintCompareFunction(const void *a, const void *b);
void clearElement(print_element *e);
void printElement(print_element *e);

#endif
