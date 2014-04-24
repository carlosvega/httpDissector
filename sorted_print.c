#include "sorted_print.h"

extern FILE *output;
extern struct args_parse options;

unsigned long print_element_counter = 0; 

print_element *print_element_list = NULL;

void initPrintElementList(){
    print_element_list = calloc(PRINT_POOL_SIZE, sizeof(print_element));
}

void freePrintElementList(){
    sortPrintElements();
    printElements();
    FREE(print_element_list);
}

void addPrintElement(char *ip_client, char *ip_server,
 unsigned short port_client, unsigned short port_server,
 struct timespec req_ts, struct timespec res_ts, struct timespec diff,
 short responseCode, char *response_msg, char *host, char *url, http_op op){

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
    strncpy(print_element_list[print_element_counter].host, host, HOST_SIZE);
    print_element_list[print_element_counter].op = op;

    print_element_counter++;

    if(print_element_counter == PRINT_POOL_SIZE){
        sortPrintElements();
        printElements();
    }

    return;
}

void sortPrintElements(){
    qsort(print_element_list, print_element_counter, sizeof(print_element), sortedPrintCompareFunction);
}

void printElements(){

    unsigned long i; 
    for(i=0; i<print_element_counter; i++){
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

void binary_write(print_element *e){

    in_addr_t ip_src = inet_addr(e->ip_client);
    in_addr_t ip_dst = inet_addr(e->ip_server);

    //IPsrc
    fwrite(&ip_src, sizeof(in_addr_t), 1, output);
    //PortSRC
    fwrite(&e->port_client, sizeof(short), 1, output);
    //IPdst
    fwrite(&ip_dst, sizeof(in_addr_t), 1, output);
    //PortDST
    fwrite(&e->port_server, sizeof(short), 1, output);
    //req_ts
    fwrite(&e->req_ts, sizeof(struct timespec), 1, output);
    //res_ts
    fwrite(&e->res_ts, sizeof(struct timespec), 1, output);
    //diff
    fwrite(&e->diff, sizeof(struct timespec), 1, output);
    //size of response msg and response msg
    fwrite(e->response_msg, sizeof(char), RESP_MSG_SIZE, output);
    //response code
    fwrite(&e->responseCode, sizeof(short), 1, output);
    //method
    char *aux = http_op_to_char(e->op);
    char method[8] = {0};
    memcpy(method, aux, strlen(aux));
    fwrite(method, sizeof(char), 8, output);
    //size of the host and host
    fwrite(e->host, sizeof(char), HOST_SIZE, output);
    //size of the url and url
    fwrite(e->url, sizeof(char), URL_SIZE, output);
}

void printElement(print_element *e){

    if(options.binary){
        binary_write(e);
    }else{
        if(options.index != NULL){
            fflush(output);
            write_to_index_with_ts(ftell(output), e->req_ts);
        }

        fprintf(output, "%s|%i|%s|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s|%s\n", 
            e->ip_client, e->port_client, e->ip_server, 
            e->port_server, e->req_ts.tv_sec, e->req_ts.tv_nsec, e->res_ts.tv_sec, 
            e->res_ts.tv_nsec, e->diff.tv_sec, e->diff.tv_nsec, RESP_MSG_SIZE, e->response_msg, 
            e->responseCode, http_op_to_char(e->op), e->host, e->url);
    }

    return;
}

