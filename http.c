#include "http.h"

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

extern struct msgbuf sbuf;
extern struct args_parse *options;
#define CADENA_SIZE 3072
#define CADENA_AUX_SIZE 256

// char aux_str[MAX_PAYLOAD_STRING];

struct _internal_http_packet {
	http_header *headers;
	char *data;
	http_op op;
	char method[32];
	char version[32];
	char agent[2048];
	char uri[2048];
	char host[256];
	int response_code;
	char response_msg[256];
	short has_host;
	short has_agent;
};

// pcre_extra *pcreExtra;
// pcre *hostname_regex;
regex_t hostname_regex;
// u_char u_cadena[CADENA_SIZE];
char cadena_aux[CADENA_SIZE];

http_header *http_get_headers(http_packet http)
{

	if (http == NULL || http->headers == NULL) {
		return NULL;
	}

	return http->headers;
}

int http_is_request(http_op h)
{
	switch (h) {
	case GET:
		return 1;

	case HEAD:
		return 1;

	case RESPONSE:
		return 0;

	case POST:
		return 1;

	case PUT:
		return 1;

	case DELETE:
		return 1;

	case TRACE:
		return 1;

	case OPTIONS:
		return 1;

	case CONNECT:
		return 1;

	case PATCH:
		return 1;

	default:
		return 0;
	}
}

char *http_get_data(http_packet http)
{
	if (!http || !http->data) {
		return NULL;
	}

	return http->data;
}

http_op http_get_op(http_packet http)
{
	if (!http) {
		return 0;
	}

	return http->op;
}

char *http_get_method(http_packet http)
{
	if (!http || !http->method) {
		return NULL;
	}

	return http->method;
}

char *http_op_to_char(http_op h)
{
	switch (h) {
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

char *http_get_version(http_packet http)
{
	if (!http || !http->version) {
		return NULL;
	}

	return http->version;
}

char *http_get_uri(http_packet http)
{
	if (!http || !http->uri) {
		return NULL;
	}

	return http->uri;
}

char *http_get_host(http_packet http)
{
	if (!http || !http->host) {
		return NULL;
	}

	return http->host;
}

char *http_get_agent(http_packet http)
{
	if (!http || !http->agent) {
		return NULL;
	}

	return http->agent;
}

int http_get_response_code(http_packet http)
{
	if (!http) {
		return -1;
	}

	return http->response_code;
}

char *http_get_response_msg(http_packet http)
{
	if (!http || !http->response_msg) {
		return NULL;
	}

	return http->response_msg;
}

http_op http_which_method(u_char *tcp_payload)
{

	if (tcp_payload == NULL) {
		return ERR;
	}

	char method[16] = {0};

	memcpy(method, tcp_payload, 8);

	switch (method[0]) {
	case 'G':

		//GET
		if (strncmp("ET ", method + 1, 3) == 0) {
			return GET;
		}

		break;

	case 'H':

		//HTTP or HEAD
		if (strncmp("TTP/", method + 1, 4) == 0) {
			return RESPONSE;
		}

		if (strncmp("EAD ", method + 1, 4) == 0) {
			return HEAD;
		}

		break;

	case 'C':

		//CONNECT
		if (strncmp("ONNECT ", method + 1, 7) == 0) {
			return CONNECT;
		}

		break;

	case 'P':

		//POST, PUT or PATCH
		if (strncmp("OST ", method + 1, 4) == 0) {
			return POST;
		}

		if (strncmp("UT ", method + 1, 3) == 0) {
			return PUT;
		}

		if (strncmp("ATCH ", method + 1, 5) == 0) {
			return PATCH;
		}

		break;

	case 'D':

		//DELETE
		if (strncmp("ELETE ", method + 1, 6) == 0) {
			return DELETE;
		}

		break;

	case 'O':

		//OPTIONS
		if (strncmp("PTIONS ", method + 1, 7) == 0) {
			return OPTIONS;
		}

		break;

	default:
		return ERR;
	}

	/*
		if(strncmp("GET ", method, 4) == 0){
			return GET;
		}else if(strncmp("HTTP/", method, 5) == 0){
	                return RESPONSE;
	        }else if(strncmp("HEAD ", method, 5) == 0){
			return HEAD;
		}else if(strncmp("POST ", method, 5) == 0){
			return POST;
		}else if(strncmp("PUT ", method, 4) == 0){
			return PUT;
		}else if(strncmp("DELETE ", method, 7) == 0){
			return DELETE;
		}else if(strncmp("TRACE ", method, 6) == 0){
			return TRACE;
		}else if(strncmp("OPTIONS ", method, 8) == 0){
			return OPTIONS;
		}else if(strncmp("CONNECT ", method, 8) == 0){
			return CONNECT;
		}else if(strncmp("PATCH ", method, 6) == 0){
			return PATCH;
		}
	*/
	return ERR;
}

http_op check_op_from_payload(u_char *tcp_payload, int length)
{
	if (length <= 0 || tcp_payload == NULL) {
		return ERR;
	}

	return http_which_method(tcp_payload);
}

int http_parse_packet(u_char *tcp_payload, int length, http_packet *http_t, struct in_addr ip_src, struct in_addr ip_dst)
{

	if (length <= 0 || http_t == NULL || tcp_payload == NULL) {
		return -1;
	}

	// if(http_alloc(http_t) == -1){
	// 	return -1;
	// }

	// int no_data = 0;
	// char *aux_hdr = NULL;
	struct _internal_http_packet *http = *http_t;
	http->headers = NULL;
	http->data = NULL;
	http->op = http_which_method(tcp_payload);

	if (http->op == ERR) {
		return -1;
	}

	// memset(u_cadena, 0, CADENA_SIZE);

	// memcpy(u_cadena, tcp_payload, MIN(CADENA_SIZE, length));

	// char *cadena = (char *) u_cadena;

	char *cadena = (char *) tcp_payload;
	cadena[MIN(CADENA_SIZE, length) - 1] = 0;

	http->has_host = 0;

	if (http->op != RESPONSE) { //REQUEST
		sscanf(cadena, "%32s %2048s %32s\r\n", http->method, http->uri, http->version);
		char *host = get_host_from_headers(cadena);

		if (host == NULL) {
			http->has_host = 0;
			inet_ntop(AF_INET, &ip_dst, http->host, 16);

		} else {
			strncpy(http->host, host, HOST_SIZE);
			http->has_host = 1;
		}

		if (options->agent) {
			char *agent = get_user_agent_from_headers(cadena);

			if (agent == NULL) {
				http->has_agent = 0;
				strcpy(http->agent, "no agent");

			} else {
				strncpy(http->agent, agent, AGENT_SIZE);
				http->has_agent = 1;
			}
		}

	} else { //RESPONSE
		char *i = strstr(cadena, "\r\n");
		short ret = 0;

		if (i != NULL) {
			cadena[i - cadena] = 0;
		}

		ret = sscanf(cadena, "%32s %d %[^\r\n]\r\n", http->version, &http->response_code, http->response_msg);

		if (ret < 2) {
			http->response_code = -1;
		}

	}

	// FREE(cadena);
	return 0;
}

void print_http_event(http_event *event, FILE *output_file)
{
	unsigned char ip_client[4] = {0};
	unsigned char ip_server[4] = {0};
	*(unsigned int *) ip_client = event->key.ip_src;
	*(unsigned int *) ip_server = event->key.ip_dst;
	struct timespec diff = tsSubtract(event->ts_res,  event->ts_req);

	fprintf(output_file, "%d.%d.%d.%d|%i|%d.%d.%d.%d|%i|%ld.%09ld|%ld.%09ld|%ld.%09ld|%.*s|%d|%s|%s|%s|%s\n",
			ip_client[0], ip_client[1], ip_client[2], ip_client[3],
			event->key.port_src, ip_server[0], ip_server[1], ip_server[2], ip_server[3],
			event->key.port_dst, event->ts_req.tv_sec, event->ts_req.tv_nsec, event->ts_res.tv_sec, event->ts_res.tv_nsec, diff.tv_sec, diff.tv_nsec,
			RESP_MSG_SIZE, event->response_msg, event->response_code, http_op_to_char(event->method), event->agent, event->host, event->url);
}

int http_fill_event(u_char *tcp_payload, int length, http_event *event, http_op op)
{
	//TODO
	//Hacer que compruebe que esta esperando, tener cuidado con las copias secundarias
	//Comprobar si la transaccion estaria completa y cambiar la variable convenientemente

	if (op == ERR) {
		fprintf(stderr, "OP ERR\n");
		return -1;
	}

	char *cadena = (char *) tcp_payload;
	cadena[MIN(CADENA_SIZE, length) - 1] = 0;
	char version[32] = {0};

	//RESPONSE
	if (op == RESPONSE) {
		char *i = strstr(cadena, "\r\n");
		short ret = 0;

		if (i != NULL) {
			cadena[i - cadena] = 0;
		}

		ret = sscanf(cadena, "%32s %hd %[^\r\n]\r\n", version, &event->response_code, event->response_msg);

		if (ret < 2) {
			event->response_code = -1;
		}

		event->response_msg[RESP_MSG_SIZE - 1] = 0;

		//CHANGE STATUS
		if (event->status == WAITING_RESPONSE) {
			event->status = TRANSACTION_COMPLETE;

		} else if (event->status == EMPTY) {
			event->status = WAITING_REQUEST;
		}

	} else { //REQUEST
		event->method = op;
		char method[32];
		sscanf(cadena, "%32s %2048s %32s\r\n", method, event->url, version);
		char *host = get_host_from_headers(cadena);

		if (host == NULL) {
			inet_ntop(AF_INET, &event->key.ip_dst, event->host, 16);
		}else{
			strncpy(event->host, host, HOST_SIZE);
		}

		if (options->agent) {
			char *agent = get_user_agent_from_headers(cadena);

			if (agent == NULL) {
				strcpy(event->agent, "no agent");

			} else {
				strncpy(event->agent, agent, AGENT_SIZE);
			}
		}

		//CHANGE STATUS
		if (event->status == WAITING_REQUEST) {
			event->status = TRANSACTION_COMPLETE;

		} else if (event->status == EMPTY) {
			event->status = WAITING_RESPONSE;
		}

	}

	return 0;
}

int http_parse_packet_with_op(u_char *tcp_payload, int length, http_packet *http_t, struct in_addr ip_src, struct in_addr ip_dst, http_op op)
{

	if (length <= 0 || http_t == NULL || tcp_payload == NULL) {
		return -1;
	}

	struct _internal_http_packet *http = *http_t;

	http->headers = NULL;

	http->data = NULL;

	// http->op = http_which_method(tcp_payload);

	if (http->op == ERR) {
		return -1;
	}

	char *cadena = (char *) tcp_payload;
	cadena[MIN(CADENA_SIZE, length) - 1] = 0;

	http->has_host = 0;

	if (http->op != RESPONSE) { //REQUEST
		sscanf(cadena, "%32s %2048s %32s\r\n", http->method, http->uri, http->version);
		char *host = get_host_from_headers(cadena);

		if (host == NULL) {
			http->has_host = 0;
			inet_ntop(AF_INET, &ip_dst, http->host, 16);

		} else {
			strncpy(http->host, host, HOST_SIZE);
			http->has_host = 1;
		}

		if (options->agent) {
			char *agent = get_user_agent_from_headers(cadena);

			if (agent == NULL) {
				http->has_agent = 0;
				strcpy(http->agent, "no agent");

			} else {
				strncpy(http->agent, agent, AGENT_SIZE);
				http->has_agent = 1;
			}
		}

	} else { //RESPONSE
		char *i = strstr(cadena, "\r\n");
		short ret = 0;

		if (i != NULL) {
			cadena[i - cadena] = 0;
		}

		ret = sscanf(cadena, "%32s %d %[^\r\n]\r\n", http->version, &http->response_code, http->response_msg);

		if (ret < 2) {
			http->response_code = -1;
		}

	}

	return 0;
}

int http_parse_headers(http_packet *http_t, char *cadena, int length)
{
	struct _internal_http_packet *http = *http_t;

	int ret = 0;
	int no_data = 0;
	char *aux_hdr = NULL;

	char *hdr = strstr(cadena, "\r\n");

	if (hdr == NULL) {
		return -3;
	}

	char *data = strstr(cadena, "\r\n\r\n");

	if (data == NULL) {
		no_data = 1;
		data = cadena + length + 1;
	}

	//Copy HTTP headers
	if (no_data == 0) {
		data += 2; //Jump \r\n, THE HEADERS MUST END WITH \r\n
	}

	hdr += 2; //Jump \r\n
	aux_hdr = (char *) calloc(((data - hdr) + 1), sizeof(char));

	if (aux_hdr == NULL) {
		return -4;
	}

	memcpy(aux_hdr, hdr, data - hdr);

	if (no_data == 0 && *data == '\r') {
		data += 2;    //Jump \r\n of the empty line
	}

	http->headers = (http_header *) calloc(sizeof(http_header), 1);

	if (http->headers == NULL) {
		FREE(aux_hdr);
		return -5;
	}

	ret = getLines(aux_hdr, http->headers);

	FREE(aux_hdr);
	return ret;
}

char *get_user_agent_from_headers(char *cadena)
{


	memset(cadena_aux, 0, CADENA_AUX_SIZE);

	char *host_1 = strstr(cadena, "User-Agent");

	if (host_1 != NULL) {
		int ret = sscanf(host_1, "User-Agent: %s\r\n", cadena_aux);

		if (ret == 1) {
			return cadena_aux;

		} else {
			return NULL;
		}

	} else {
		return NULL;
	}

	return cadena_aux;
}

char *get_host_from_headers(char *cadena)
{

	int reti, ret;

	memset(cadena_aux, 0, CADENA_AUX_SIZE);
	char *host_1 = strstr(cadena, "Host");

	if (unlikely(host_1 != NULL)) {

		ret = sscanf(host_1, "Host: %s\r\n", cadena_aux);

		if (likely(ret == 1)) {
			if (likely(options->fqdn == 0)) {
				return cadena_aux;

			} else if (options->fqdn == 1) {
				reti = regexec(&hostname_regex, cadena_aux, 0, NULL, 0);

				if (!reti) {
					return cadena_aux;
				}
			}
		}
	}

	return NULL;
}

// char *get_host_from_headers(char *cadena){

// 	int reti;

// 	memset(cadena_aux, 0, CADENA_AUX_SIZE);
// 	char *host_1 = strstr(cadena, "Host");
// 	if(host_1 != NULL){
// 		sscanf (host_1, "Host: %s\r\n", cadena_aux);

// 		reti = pcre_exec(hostname_regex, pcreExtra, cadena_aux, strlen(cadena_aux), 0, 0, NULL, 0);
// 		if(reti < 0){
// 			switch(reti) {
// 		      case PCRE_ERROR_NOMATCH      : //printf("String did not match the pattern (%s)\n", cadena_aux);
// 		      break;
// 		      case PCRE_ERROR_NULL         : printf("Something was null\n");                      break;
// 		      case PCRE_ERROR_BADOPTION    : printf("A bad option was passed\n");                 break;
// 		      case PCRE_ERROR_BADMAGIC     : printf("Magic number bad (compiled re corrupt?)\n"); break;
// 		      case PCRE_ERROR_UNKNOWN_NODE : printf("Something kooky in the compiled re\n");      break;
// 		      case PCRE_ERROR_NOMEMORY     : printf("Ran out of memory\n");                       break;
// 		      default                      : printf("Unknown error\n");                           break;
// 			}
// 			return NULL;
// 		}else{
// 			return cadena_aux;
// 		}

// 	}else{
// 		return NULL;
// 	}

// 	return cadena_aux;
// }

void http_print_headers(http_packet *http_t)
{


	if (http_t == NULL) {
		return;
	}

	struct _internal_http_packet *http = *http_t;

	if (http == NULL) {
		return;
	}

	if (http->headers == NULL) {
		return;
	}

	list_node *ls = http->headers->fields;

	while (ls != NULL) {
		fprintf(stdout, "%s: %s\n", ls->key, ls->value);
		ls = ls->next;
	}

	return;
}

int http_clean_up(http_packet *http_t)
{

	if (http_t == 0) {
		return -1;
	}

	struct _internal_http_packet *http = *http_t;

	if (http == 0) {
		return -1;
	}

	FREE(http->data);

	// memset(http->method, 0, 32);
	// memset(http->version, 0, 32);
	// memset(http->uri, 0, 2048);
	// memset(http->host, 0, 256);
	// memset(http->response_msg, 0, 256);
	// http->has_host = 0;
	// http->op = 0;
	// http->response_code = 0;

	http_free_header(http->headers);
	memset(http, 0, sizeof(*http));

	return 0;
}

int http_alloc(http_packet *http_t)
{

	/* Compile regular expression */
	// const char *pcreErrorStr;
	// int pcreErrorOffset;
	// hostname_regex = pcre_compile("([a-zA-Z0-9\\.\\-]+\\.[a-zA-Z0-9\\.\\-]+[\\.]*[a-zA-Z0-9\\.\\-]+)", 0, &pcreErrorStr, &pcreErrorOffset, NULL);
	// if(hostname_regex == NULL) {
//    	printf("ERROR: Could not compile '%s': %s\n", "([a-zA-Z0-9\\.\\-]+\\.[a-zA-Z0-9\\.\\-]+[\\.]*[a-zA-Z0-9\\.\\-]+)", pcreErrorStr);
//    	exit(1);
//  	}
//  	pcreExtra = pcre_study(hostname_regex, 0, &pcreErrorStr);
//  	if(pcreErrorStr != NULL) {
//    	printf("ERROR: Could not study '%s': %s\n", "([a-zA-Z0-9\\.\\-]+\\.[a-zA-Z0-9\\.\\-]+[\\.]*[a-zA-Z0-9\\.\\-]+)", pcreErrorStr);
//    	exit(1);
//  	}

	/* Compile regular expression */
	int reti = regcomp(&hostname_regex, "([a-zA-Z0-9\\.\\-]+\\.[a-zA-Z0-9\\.\\-]+[\\.]*[a-zA-Z0-9\\.\\-]+)", REG_EXTENDED);

	if (reti) {
		fprintf(stderr, "Could not compile regex\n");
		exit(1);
	}


	struct _internal_http_packet *http;

	http = (struct _internal_http_packet *) calloc(1, sizeof(* http));

	if (http == NULL) {
		return -1;
	}

	http->data = NULL;

	memset(http, 0, sizeof(*http));
	*http_t = http;

	return 0;
}

void http_free_packet(http_packet *http_t)
{

	/* Free compiled regular expression if you want to use the regex_t again */
	// pcre_free(hostname_regex);
//    if(pcreExtra != NULL)
//    	pcre_free(pcreExtra);

	/* Free compiled regular expression if you want to use the regex_t again */
	regfree(&hostname_regex);

	if (http_t == NULL || *http_t == NULL) {
		return;
	}

	struct _internal_http_packet *http = *http_t;

	if (http == NULL) {
		return;
	}

	FREE(http->data);

	if (http->headers != NULL) {
		http_free_header(http->headers);
		FREE(http->headers);
	}

	if (http_t != NULL) {
		if (*http_t != NULL) {
			FREE(http);
		}
	}

	http = NULL;
	*http_t = NULL;

	return;
}
