#include "http.h"
#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "args_parse.h"

extern struct msgbuf sbuf;
extern struct args_parse options;
#define ERR_MSG(...) do{if(options.debug){fprintf(stderr, __VA_ARGS__);}}while(0)
#define CADENA_SIZE 3072
#define CADENA_AUX_SIZE 256

// char aux_str[MAX_PAYLOAD_STRING];

struct _internal_http_packet{
	http_header *headers;
	char *data;
	http_op op;
	char method[32];
	char version[32];
	char uri[2048];
	char host[256];
	int response_code;
	char response_msg[256];
	short has_host;
};

regex_t hostname_regex;
char cadena[CADENA_SIZE];
char cadena_aux[CADENA_AUX_SIZE];

http_header *http_get_headers(http_packet http){

	if(http == NULL || http->headers == NULL){
		return NULL;
	}
	
	return http->headers;
}

char *http_get_data(http_packet http){
	if(!http || !http->data){
		return NULL;
	}

	return http->data;
}

http_op http_get_op(http_packet http){
	if(!http){
		return 0;
	}

	return http->op;
}

char *http_get_method(http_packet http){
	if(!http || !http->method){
		return NULL;
	}

	return http->method;
}

char *http_op_to_char(http_op h){
	switch(h){
		case HEAD:
			return "HEAD";
		case GET:
			return "GET";
		case POST:
			return "POST";
		case PUT:
			return "PUT";
		case DELETE:
			return "DELETE";
		case TRACE:
			return "TRACE";
		case OPTIONS:
			return "OPTIONS";
		case CONNECT:
			return "CONNECT";
		case PATCH:
			return "PATCH";
		case RESPONSE:
			return "RESPONSE";
		default:
			return "ERR";
	}
}

char *http_get_version(http_packet http){
	if(!http || !http->version){
		return NULL;
	}

	return http->version;
}

char *http_get_uri(http_packet http){
	if(!http || !http->uri){
		return NULL;
	}

	return http->uri;
}

char *http_get_host(http_packet http){
	if(!http || !http->host){
		return NULL;
	}

	return http->host;
}

int http_get_response_code(http_packet http){
	if(!http){
		return -1;
	}

	return http->response_code;
}

char *http_get_response_msg(http_packet http){
	if(!http || !http->response_msg){
		return NULL;
	}

	return http->response_msg;
}

http_op http_which_method(char * tcp_payload){
	
	if(tcp_payload == NULL) return ERR;
	
	char method[16] = {0};

	memcpy(method, tcp_payload, 8);

	if(strncmp("GET", method, 3) == 0){
		return GET;
	}else if(strncmp("HTTP/", method, 5) == 0){
		return RESPONSE;
	}else if(strncmp("POST", method, 4) == 0){
		return POST;
	}else if(strncmp("HEAD", method, 4) == 0){
		return HEAD;
	}else if(strncmp("PUT", method, 3) == 0){
		return PUT;
	}else if(strncmp("DELETE", method, 6) == 0){
		return DELETE;
	}else if(strncmp("TRACE", method, 5) == 0){
		return TRACE;
	}else if(strncmp("OPTIONS", method, 7) == 0){
		return OPTIONS;
	}else if(strncmp("CONNECT", method, 7) == 0){
		return CONNECT;
	}else if(strncmp("PATCH", method, 5) == 0){
		return PATCH;
	}

	return ERR;
}

int http_parse_packet(char *tcp_payload, int length, http_packet *http_t, char *ip_addr_src, char *ip_addr_dst){

	if(length <= 0 || http_t == NULL || tcp_payload == NULL)
		return -1;
	
	int no_data = 0;
	// char *aux_hdr = NULL;
	struct _internal_http_packet *http = *http_t;
	http->headers = NULL;
	http->data = NULL;
	http->op = http_which_method(tcp_payload);

	if(http->op == ERR){
		return -1;
	}
	
	memset(cadena, 0, CADENA_SIZE);

	strncpy(cadena, tcp_payload, length);
	http->has_host = 0;
	if(http->op != RESPONSE){
		
		sscanf(cadena, "%32s %2048s %32s\r\n", http->method, http->uri, http->version);
		
		char *host = get_host_from_headers(cadena);
		
		if(host == NULL){
			http->has_host = 0;
			strcpy(http->host, ip_addr_dst);
		}else{
			strcpy(http->host, host);
			http->has_host = 1;
		}

	}else{
		strcpy(http->method, "RESPONSE");
		sscanf(cadena, "%32s %d %[^\r\n]\r\n", http->version, &http->response_code, http->response_msg);
		
		char *hdr = strstr(cadena, "\r\n");
		if(hdr == NULL){ 
			// FREE(cadena);
			return -1;
		}
		
		char *data = strstr(cadena, "\r\n\r\n");
		if(data == NULL){
			no_data = 1;
			data = cadena+length+1;
		}

		if(no_data == 0){
			//Copy HTTP data
			// http->data = strdup(data);
			// if(http->data == NULL){
			// 	return -1;
			// }
		}
	}

	// FREE(cadena);
	return 0;
} 

int http_parse_headers(http_packet *http_t, char *cadena, int length){
	struct _internal_http_packet *http = *http_t;

		int ret = 0;
		int no_data = 0;
		char *aux_hdr = NULL;

		char *hdr = strstr(cadena, "\r\n");
		if(hdr == NULL){ 
			return -3;
		}
		
		char *data = strstr(cadena, "\r\n\r\n");
		if(data == NULL){
			no_data = 1;
			data = cadena+length+1;
		}

		//Copy HTTP headers
		if(no_data == 0){
			data+=2; //Jump \r\n, THE HEADERS MUST END WITH \r\n
		}
		
		hdr+=2; //Jump \r\n
		aux_hdr = (char*) calloc(((data-hdr)+1),sizeof(char));
		if(aux_hdr == NULL){
			return -4;
		}

		memcpy(aux_hdr, hdr, data-hdr);
		
		if(no_data == 0 && *data == '\r')
			data+=2;	//Jump \r\n of the empty line

		http->headers = (http_header *) calloc(sizeof(http_header), 1);
		if(http->headers == NULL){
			FREE(aux_hdr);
			return -5;
		}
		
		ret = getLines(aux_hdr, http->headers);
		
		FREE(aux_hdr);
		return ret;
}

char *get_host_from_headers(char *cadena){

	int reti;

	memset(cadena_aux, 0, CADENA_AUX_SIZE);
	char *host_1 = strstr(cadena, "Host");
	if(host_1 != NULL){		
		sscanf (host_1, "Host: %s\r\n", cadena_aux);

		/* Execute regular expression */
		reti = regexec(&hostname_regex, cadena_aux, 0, NULL, 0);
	    if( !reti ){
	        return cadena_aux;
	    }
	    else{
	        return NULL;
	    }
	}else{
		return NULL;
	}

	return cadena_aux;
}

void http_print_headers(http_packet *http_t){


	if(http_t == NULL){
		 return;
	}

	struct _internal_http_packet *http = *http_t;
	if(http == NULL){
		return;
	}
	
	if(http->headers == NULL){
		return;
	}

	list_node *ls = http->headers->fields;
	while(ls != NULL){
		fprintf(stdout, "%s: %s\n", ls->key, ls->value);
		ls = ls->next;
	}
	
	return;
}

int http_clean_up(http_packet *http_t){

	if(http_t == 0) return -1;

	struct _internal_http_packet *http = *http_t;
	if(http == 0)
		return -1;

	FREE(http->data);

	http_free_header(http->headers);
	memset(http, 0, sizeof(*http));

	return 0;
}

int http_alloc(http_packet *http_t){
	
	/* Compile regular expression */
	int reti = regcomp(&hostname_regex, "([a-zA-Z0-9\\.\\-]+\\.[a-zA-Z0-9\\.\\-]+[\\.]*[a-zA-Z0-9\\.\\-]+)", REG_EXTENDED);
    if( reti ){ fprintf(stderr, "Could not compile regex\n"); exit(1); }

	struct _internal_http_packet *http;
	
	http = (struct _internal_http_packet *) malloc(sizeof(* http));
	if(http == NULL){
		return -1;
	}
	
	http->data = NULL;

	memset(http, 0, sizeof(*http));
	*http_t = http;

	return 0;
}

void http_free_packet(http_packet *http_t){
	
	if(http_t == 0) return;
	
	if(options.debug > 1){
		ERR_MSG("DEBUG/ http_free_packet 1, ");
	}

	struct _internal_http_packet *http = *http_t;
	if(http == 0)
		return;

	if(options.debug > 1){
		ERR_MSG("2, ");
	}

	FREE(http->data);

	if(options.debug > 1){
		ERR_MSG("3, [");
	}

	if(http->headers != NULL){
		http_free_header(http->headers);

		if(options.debug > 1){
			ERR_MSG("], 4, ");
		}

		FREE(http->headers);
	}

	if(options.debug > 1){
		ERR_MSG("5, ");
	}

	if(http_t != 0){
		if(*http_t != 0){
			FREE(http);
		}
	}
		
	http=NULL;
	*http_t = NULL;

	if(options.debug > 1){
		ERR_MSG("6.\n");
	}
	
	/* Free compiled regular expression if you want to use the regex_t again */
    regfree(&hostname_regex);

	return;
}
