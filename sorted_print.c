#include "sorted_print.h"
#include "counters.h"

extern FILE *output;
extern struct args_parse options;

unsigned long print_element_counter = 0; 

print_element *print_element_list = NULL;

void initPrintElementList(){
    print_element_list = calloc(PRINT_POOL_SIZE, sizeof(print_element));
    setvbuf (output, NULL, _IONBF, BUFSIZ);
}

void freePrintElementList(){
    if(options.noRtx){
        tagRetransmissions();
    }
    sortPrintElements();
    printElements();
    FREE(print_element_list);
}

void addPrintElement(in_addr_t ip_client_int, in_addr_t ip_server_int,
 unsigned short port_client, unsigned short port_server,
 struct timespec req_ts, struct timespec res_ts, struct timespec diff,
 short responseCode, char *response_msg, char *host, char *url, http_op op, tcp_seq seq){

    //COPY ELEMENT
    // strncpy(print_element_list[print_element_counter].ip_client, ip_client, ADDR_CONST);
    // strncpy(print_element_list[print_element_counter].ip_server, ip_server, ADDR_CONST);
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
    print_element_list[print_element_counter].seq = seq;
    print_element_list[print_element_counter].isRtx = false;
    print_element_list[print_element_counter].ip_client_int = ip_client_int;
    print_element_list[print_element_counter].ip_server_int = ip_server_int;

    print_element_counter++;

    if(print_element_counter == PRINT_POOL_SIZE){
        if(options.noRtx){
            tagRetransmissions();
        }
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

int isRtx(print_element *a, print_element *b){
    // return (a->ip_client_int == b->ip_client_int &&
    //         a->ip_server_int == b->ip_server_int &&
    //         a->port_client   == b->port_client   &&
    //         a->port_server   == b->port_server   &&
    //         a->seq           == b->seq) 
    // ? 1 : 0;

    return !memcmp(a, b, sizeof(in_addr_t)*2 + sizeof(unsigned short)*2 + sizeof(tcp_seq));
}

void tagRetransmissions(){
    qsort(print_element_list, print_element_counter, sizeof(print_element), sortedRemoveRetransmissionsCompareFunction);
    int i;
    for(i=0; i<print_element_counter-1; i++){
        if(isRtx(&print_element_list[i], &print_element_list[i+1])){
            print_element_list[i+1].isRtx = true;
            increment_rtx_counter(1);
            decrement_request_counter(print_element_list[i].op);
        }
    }
}

int sortedRemoveRetransmissionsCompareFunction(const void *a, const void *b){

    print_element *c = (print_element *)a;
    print_element *d = (print_element *)b;

    if (c->ip_client_int != d->ip_client_int){
        return c->ip_client_int - d->ip_client_int;
    }

    if (c->port_client != d->port_client){
        return c->port_client - d->port_client;
    }

    if (c->ip_server_int != d->ip_server_int){
        return c->ip_server_int - d->ip_server_int;
    }   

    if (c->port_server != d->port_server){
        return c->port_server - d->port_server;
    }

    if(c->seq != d->seq){
        return c->seq - d->seq;
    }

    return tsCompare (c->req_ts, d->req_ts);
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

    // in_addr_t ip_src = inet_addr(e->ip_client);
    // in_addr_t ip_dst = inet_addr(e->ip_server);

    // //IPsrc
    // fwrite(&ip_src, sizeof(in_addr_t), 1, output);
    // //PortSRC
    // fwrite(&e->port_client, sizeof(short), 1, output);
    // //IPdst
    // fwrite(&ip_dst, sizeof(in_addr_t), 1, output);
    // //PortDST
    // fwrite(&e->port_server, sizeof(short), 1, output);
    // //req_ts
    // fwrite(&e->req_ts, sizeof(struct timespec), 1, output);
    // //res_ts
    // fwrite(&e->res_ts, sizeof(struct timespec), 1, output);
    // //diff
    // fwrite(&e->diff, sizeof(struct timespec), 1, output);
    // //size of response msg and response msg
    // fwrite(e->response_msg, sizeof(char), RESP_MSG_SIZE, output);
    // //response code
    // fwrite(&e->responseCode, sizeof(short), 1, output);
    // //method
    // char *aux = http_op_to_char(e->op);
    // char method[8] = {0};
    // memcpy(method, aux, strlen(aux));
    // fwrite(method, sizeof(char), 8, output);
    // //size of the host and host
    // fwrite(e->host, sizeof(char), HOST_SIZE, output);
    // //size of the url and url
    // fwrite(e->url, sizeof(char), URL_SIZE, output);
}

void printElement(print_element *e){

    if(e->isRtx == true){
        return;
    }

    if(options.binary){
        binary_write(e);
    }else if(options.rrd){
        printRRD(e->req_ts, e->diff);
    }else{
        // if(options.index != NULL){
        //     fflush(output);
        //     write_to_index_with_ts(ftell(output), e->req_ts);
        // }

        //IPS TO PRETTY PRINT NUMBER VECTOR
        unsigned char ip_client[4] = {0};
        unsigned char ip_server[4] = {0};
        *(unsigned int *) ip_client = e->ip_client_int;
        *(unsigned int *) ip_server = e->ip_server_int;

        fprintf(output, "%d.%d.%d.%d|%i|%d.%d.%d.%d|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s|%s\n", 
            ip_client[0], ip_client[1], ip_client[2], ip_client[3], 
            e->port_client, ip_server[0], ip_server[1], ip_server[2], ip_server[3], 
            e->port_server, e->req_ts.tv_sec, e->req_ts.tv_nsec, e->res_ts.tv_sec, e->res_ts.tv_nsec, e->diff.tv_sec, e->diff.tv_nsec, 
            RESP_MSG_SIZE, e->response_msg, e->responseCode, http_op_to_char(e->op), e->host, e->url);   

        fflush(output);
        // free(ip_client);
        // free(ip_server);
    }

    return;
}

uint32_t getIndexFromPrintlement(print_element *e){
    return getIndex_global(e->ip_client_int, e->ip_server_int, e->port_client, e->port_server);
}
