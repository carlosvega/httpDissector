#ifndef _sorted_print_H
#define _sorted_print_H

#include <string.h>
#include "list.h"
#include "args_parse.h"
#include "index.h"
#include "tools.h"
#include "http.h"

#define PRINT_POOL_SIZE 1000000

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
  char  host[HOST_SIZE];
  http_op op;
} print_element;

void addPrintElement(char *ip_client, char *ip_server,
 unsigned short port_client, unsigned short port_server,
 struct timespec req_ts, struct timespec res_ts, struct timespec diff,
 short responseCode, char *response_msg, char *host, char *url, http_op op);

void initPrintElementList();
void freePrintElementList();
void sortPrintElements();
void printElements();
int sortedPrintCompareFunction(const void *a, const void *b);
void clearElement(print_element *e);
void printElement(print_element *e);

#endif
