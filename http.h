#ifndef _http
#define _http
#include "alist.h"

typedef enum {HEAD = 0, GET, POST, PUT, DELETE, TRACE, OPTIONS, CONNECT, PATCH, RESPONSE, ERR} http_op;

typedef struct _internal_http_packet * http_packet;

http_op http_which_method(char * tcp_payload);
int http_parse_packet(char *tcp_payload, int length, http_packet *http);

http_header *http_get_headers(http_packet http);
char *http_get_data(http_packet http);
http_op http_get_op(http_packet http);
char *http_get_method(http_packet http);
char *http_get_version(http_packet http);
char *http_get_uri(http_packet http);
char *http_get_host(http_packet http);
int http_get_response_code(http_packet http);
char *http_get_response_msg(http_packet http);
void http_print_headers(http_packet *http_t);
int http_parse_headers(http_packet *http_t, char *cadena, int length);
int http_alloc(http_packet *http_t);
void http_free_packet(http_packet *http);

#endif