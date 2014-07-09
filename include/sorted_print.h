#ifndef _sorted_print_H
#define _sorted_print_H

#include <string.h>
#include "list.h"
#include "args_parse.h"

#include "connection.h"
#include "index.h"
#include "tools.h"
#include "http.h"
#include <arpa/inet.h>

#define PRINT_POOL_SIZE 1000000

typedef enum { false, true } bool;

typedef struct {
  //IPs, ports & seq
  in_addr_t ip_client_int;
  in_addr_t ip_server_int;
  unsigned short port_client;
  unsigned short port_server;
  tcp_seq seq;

  // char ip_client[ADDR_CONST];
  // char ip_server[ADDR_CONST];
  
  //Timestamps
  struct timespec req_ts;
  struct timespec res_ts;
  struct timespec diff;
  //
  short responseCode;
  char  response_msg[RESP_MSG_SIZE];
  char  url[URL_SIZE];
  char  host[HOST_SIZE];
  bool isRtx;
  http_op op;
} print_element;

void addPrintElement(in_addr_t ip_client_int, in_addr_t ip_server_int, char *ip_client, char *ip_server,
 unsigned short port_client, unsigned short port_server,
 struct timespec req_ts, struct timespec res_ts, struct timespec diff,
 short responseCode, char *response_msg, char *host, char *url, http_op op, tcp_seq seq);

int isRtx(print_element *a, print_element *b);
void tagRetransmissions();
void initPrintElementList();
void freePrintElementList();
void sortPrintElements();
void printElements();
int sortedRemoveRetransmissionsCompareFunction(const void *a, const void *b);
int sortedPrintCompareFunction(const void *a, const void *b);
void clearElement(print_element *e);
void printElement(print_element *e);

#endif
