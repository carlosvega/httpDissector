#include "request.h"

node_l static_node;

node_l *nodel_aux;

node_l *request_pool_free=NULL;
node_l *request_pool_used=NULL;
unsigned long long gottenRequests = 0;
request *requests;

float pool_requests_used_ratio(){
    return list_size(&request_pool_used) / ((float) REQUEST_POOL);
}

unsigned long long getGottenRequests(){
	return gottenRequests;
}

void allocRequestPool(void)
{
	size_t i=0;
	node_l *n=NULL;
	requests=calloc(REQUEST_POOL,sizeof(request));
	
	if(requests == NULL){
		fprintf(stderr, "Execute the program on a host with enought memory. REQUEST_POOL: %d\n", REQUEST_POOL);
	}

	assert(requests!=NULL);
	for(i=0;i<REQUEST_POOL;i++)
	{
		n=list_alloc_node(requests+i);
		list_prepend_node(&request_pool_free,n);
	}

}

request * getRequest(void)
{

	//Obtiene nodo del pool con el hashvalue nuevo
	node_l *n=list_pop_first_node(&request_pool_free);

	if(request_pool_free==NULL)
	{	fprintf(stderr, "pool request vacio\n");
		exit(-1);
	}
	//Lo mete en el pool de usados
	list_prepend_node(&request_pool_used,n);

	memset(n->data, 0, sizeof(request));				//Resetear request

	gottenRequests++;

	return  (n->data); //retorna el hashvalue
	
}

node_l *request_search(node_l *first, tcp_seq seq, int *number){

	node_l *n, *prev = NULL;
	*number = 0;

	//primero de la lista
	n = first;

	while(n!= NULL && n!=prev) {
		__builtin_prefetch (n->next);
		request *req = (request *) n->data;
		
		if(req->ack == seq){
			return n;
		}
		
		*number += 1;

		prev = n;
		n = n->next;
		if(n==first){
			break;
		}
	}

	return NULL;

}

void releaseRequest(request * f)
{
	node_l *n=list_pop_first_node(&request_pool_used);
	n->data=(void*)f;
	list_prepend_node(&request_pool_free,n);
	gottenRequests--;
}

void freeRequestPool(void)
{
	node_l *n=NULL;
	while(request_pool_free!=NULL)
	{
		n=list_pop_first_node(&request_pool_free);
		FREE(n);
	}

	while(request_pool_used!=NULL)
	{
		n=list_pop_first_node(&request_pool_used);
		FREE(n);
	}

	gottenRequests = 0;
	FREE(requests);
}

void copyRequest(request *req_old, request *req_new){
	strncpy(req_new->url, req_old->url, URL_SIZE);
	strncpy(req_new->host, req_old->host, HOST_SIZE);
	strncpy(req_new->agent, req_old->agent, AGENT_SIZE);
	req_new->op = req_old->op;
	req_new->seq = req_old->seq;
	req_new->ack = req_old->ack;
	req_new->ts = req_old->ts;
//NOT USED	req_new->aux_res = NULL;
	return;
}

void fillRequest(packet_info *packet, request *req){
	strncpy(req->url, packet->url, URL_SIZE);
	strncpy(req->host, packet->host, HOST_SIZE);
	strncpy(req->agent, packet->agent, AGENT_SIZE);
	req->op = packet->op;
	req->seq = packet->tcp->th_seq;
	req->ack = packet->tcp->th_ack;
	req->ts = packet->ts;
//NOT USED	req->aux_res = NULL;
	return;
}
