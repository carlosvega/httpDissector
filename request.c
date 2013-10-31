#include "request.h"

node_l static_node;

node_l *nodel_aux;

node_l *request_pool_free=NULL;
node_l *request_pool_used=NULL;
unsigned long long gottenRequests = 0;
request *requests;

unsigned long long getGottenRequests(){
	return gottenRequests;
}

void allocRequestPool(void)
{
	int i=0;
	node_l *n=NULL;
	requests=calloc(REQUEST_POOL,sizeof(request));
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

node_l *request_search(node_l **list, tcp_seq seq, int *number){

	node_l *n, *prev = NULL;
	*number = 0;

	assert(list != NULL);

	//primero de la lista
	n = list_get_first_node(list);

	while(n != NULL && n!=prev) {
		request *req = (request *) n->data;
		if(req->ack == seq)
			return n;
		
		prev = n;
		n = list_get_next_node(list, n);
		*number += 1;
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
		free(n);
	}

	while(request_pool_used!=NULL)
	{
		n=list_pop_first_node(&request_pool_used);
		free(n);
	}

	free(requests);
}

void fillRequest(packet_info *packet, request *req){
	strncpy(req->url, packet->url, URL_SIZE);
	req->op = packet->op;
	req->seq = packet->tcp->th_seq;
	req->ack = packet->tcp->th_ack;
	req->ts = packet->ts;
	req->aux_res = NULL;
	return;
}
