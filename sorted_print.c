#include "sorted_print.h"

extern FILE *output;

unsigned long print_element_counter = 0; 

void addPrintElement(char *ip_client, char *ip_server,
 unsigned short port_client, unsigned short port_server,
 struct timespec req_ts, struct timespec res_ts, struct timespec diff,
 short responseCode, char *response_msg, char *url, http_op op){

    //COPY ELEMENT
    strncpy(print_element_list[print_element_counter].ip_client, ip_client, ADDR_CONST);
    strncpy(print_element_list[print_element_counter].ip_server, ip_server, ADDR_CONST);
    print_element_list[print_element_counter].port_client = port_client;
    print_element_list[print_element_counter].port_server = port_server;
    print_element_list[print_element_counter].req_ts = req_ts;
    print_element_list[print_element_counter].res_ts = res_ts;
    print_element_list[print_element_counter].diff = diff;
    print_element_list[print_element_counter].responseCode = responseCode;
    strncpy(print_element_list[print_element_counter].response_msg, response_msg, RESP_MSG_SIZE);
    strncpy(print_element_list[print_element_counter].url, url, URL_SIZE);
    print_element_list[print_element_counter].op = op;

    print_element_counter++;

    if(print_element_counter == PRINT_POOL_SIZE){
        sortPrintElements();
        printElements();
    }

    return;
}

void sortPrintElements(){
    mergesort(print_element_list, PRINT_POOL_SIZE, sizeof(print_element), sortedPrintCompareFunction);
}

void printElements(){

    unsigned long i; 
    for(i=0; i<PRINT_POOL_SIZE; i++){
        printElement(&print_element_list[i]);
        clearElement(&print_element_list[i]);
    }

    print_element_counter = 0;

    return;
}

int sortedPrintCompareFunction(const void *a, const void *b){

    print_element *c = (print_element *)a;
    print_element *d = (print_element *)b;

    return tsCompare (c->req_ts, d->req_ts);
}

void clearElement(print_element *e){
    return;
}

void printElement(print_element *e){
    fprintf(output, "%s|%i|%s|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s\n", 
        e->ip_client, e->port_client, e->ip_server, 
        e->port_server, e->req_ts.tv_sec, e->req_ts.tv_nsec, e->res_ts.tv_sec, 
        e->res_ts.tv_nsec, e->diff.tv_sec, e->diff.tv_nsec, RESP_MSG_SIZE, e->response_msg, 
        e->responseCode, e->url, e->op == POST ? "POST" : "GET");    
    return;
}

