#include "http.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define safe_free(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

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
};

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
	}else if(strncmp("HEAD", method, 4) == 0){
		return HEAD;
	}else if(strncmp("POST", method, 4) == 0){
		return POST;
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
	}else if(strncmp("HTTP/", method, 5) == 0){
		return RESPONSE;
	}


	return ERR;
}

int http_parse_packet(char *tcp_payload, int length, http_packet *http_t){

	if(length <= 0 || http_t == NULL || tcp_payload == NULL)
		return -1;
		
	http_alloc(http_t);
	int no_data = 0;
	char *aux_hdr = NULL;
	struct _internal_http_packet *http = *http_t;
	http->headers = NULL;
	http->data = NULL;
	http->op = http_which_method(tcp_payload);
	if(http->op == ERR){
		return -1;
	}
	
	char *cadena = NULL;
	cadena = (char*) malloc(length+1 * sizeof(char));
	memset(cadena, 0, length+1);
	if(cadena == NULL){
		return -1;
	}

	strncpy(cadena, tcp_payload, length);

	if(http->op != RESPONSE){
		//fprintf(stderr, "HTTP: |%s|\n", cadena);
		//int ret  = sscanf(cadena, "%32s %2048s %32s\r\nHost: %256s\r\n", http->method, http->uri, http->version, http->host);
		sscanf(cadena, "%32s %2048s %32s\r\n", http->method, http->uri, http->version);
		
		int ret = http_parse_headers(&http, cadena, length);
		if(ret >= 0){
			char * caca = find("Host", http->headers->fields);
			memset(http->host, 0, 256);
		 	if(caca != NULL){
		 		strcpy(http->host, caca);
		  	}
		}
		
		
	}else{
		strcpy(http->method, "RESPONSE");
		sscanf(cadena, "%32s %d %[^\r]\r\n", http->version, &http->response_code, http->response_msg);
		char *hdr = strstr(cadena, "\r\n");
		if(hdr == NULL){ 
			free(cadena);
			return -1;
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
			free(cadena);
			return -1;
		}

		memcpy(aux_hdr, hdr, data-hdr);
		
		if(no_data == 0 && *data == '\r')
			data+=2;	//Jump \r\n of the empty line

		http->headers = (http_header *) calloc(sizeof(http_header), 1);
		if(http->headers == NULL){
			free(aux_hdr);
			free(cadena);
			return -1;
		}
		
		if(getLines(aux_hdr, http->headers) == -1){
			free(aux_hdr);
			free(cadena);
			return -1;
		}
		
		free(aux_hdr);

		if(no_data == 0){
			//Copy HTTP data
			// http->data = strdup(data);
			// if(http->data == NULL){
			// 	return -1;
			// }
		}
	}
	free(cadena);
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
			free(aux_hdr);
			return -5;
		}
		
		ret = getLines(aux_hdr, http->headers);
		
		free(aux_hdr);
		return ret;
}

void http_print_headers(http_packet *http_t){


	if(http_t == NULL){
		 return;
	}

	struct _internal_http_packet *http = *http_t;
	if(http == NULL){
		return;
	}
	
	// if(http->op != RESPONSE){
	// 	return;
	// }
	
	if(http->headers == NULL){
		return;
	}

//	fprintf(stderr, "%s\n", http->headers);

	list_node *ls = http->headers->fields;
	while(ls != NULL){
		fprintf(stdout, "%s: %s\n", ls->key, ls->value);
		ls = ls->next;
	}
	
	return;
}

int http_alloc(http_packet *http_t){
	
	struct _internal_http_packet *http;
	
	http = (struct _internal_http_packet *) malloc(sizeof(*http));
	if(http == NULL){
		return -1;
	}
	
	memset(http, 0, sizeof(*http));
	*http_t = http;

	return 0;
}

void http_free_packet(http_packet *http_t){
	
	if(http_t == NULL) return;
	
	struct _internal_http_packet *http = *http_t;
	if(http == NULL)
		return;
	
	if(http->data != NULL){
		free(http->data);
		http->data = NULL;
	}

	if(http->headers != NULL){
		http_free_header(http->headers);
		free(http->headers);
		http->headers = NULL;
	}
	
	free(http);
	
	return;
}
