#ifndef _http
#define _http
#include "alist.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
// #include <pcre.h> 
#include "tools.h"
#include "args_parse.h"
#include "dissector_structs.h"


#define FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
#define MIN(a,b) (((a)<(b))?(a):(b))


typedef struct _internal_http_packet * http_packet;

http_op http_which_method(u_char * tcp_payload);
int http_parse_packet(u_char *tcp_payload, int length, http_packet *http_t, struct in_addr ip_src, struct in_addr ip_dst);

http_op check_op_from_payload(u_char *tcp_payload, int length);
int http_fill_event(u_char *tcp_payload, int length, http_event **event, http_op op);
void print_http_event(http_event **event, FILE *output_file);

int http_is_request(http_op h);
char *http_op_to_char(http_op h);
http_header *http_get_headers(http_packet http);
char *http_get_data(http_packet http);
http_op http_get_op(http_packet http);
char *http_get_method(http_packet http);
char *http_get_version(http_packet http);
char *http_get_uri(http_packet http);
char *http_get_host(http_packet http);
char *http_get_agent(http_packet http);
int http_get_response_code(http_packet http);
char *http_get_response_msg(http_packet http);
void http_print_headers(http_packet *http_t);
int http_parse_headers(http_packet *http_t, char *cadena, int length);
int http_alloc(http_packet *http_t);
void http_free_packet(http_packet *http);
int http_clean_up(http_packet *http);
char *get_host_from_headers(char *cadena);
char *get_user_agent_from_headers(char *cadena);

#endif