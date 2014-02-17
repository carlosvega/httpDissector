#include "response.h"

node_l static_node;

node_l *nodel_aux;

node_l *response_pool_free=NULL;
node_l *response_pool_used=NULL;
uint32_t gottenResponses = 0;
response *responses;

uint32_t getGottenResponses(){
	return gottenResponses;
}

void allocResponsePool(void)
{
	int i=0;
	node_l *n=NULL;
	responses=calloc(RESPONSE_POOL,sizeof(response));

	if(responses == NULL){
		fprintf(stderr, "Execute the program on a host with enought memory.\n");
	}

	assert(responses!=NULL);
	for(i=0;i<RESPONSE_POOL;i++)
	{
		n=list_alloc_node(responses+i);
		list_prepend_node(&response_pool_free,n);
	}

}

response * getResponse(void)
{

	//Obtiene nodo del pool con el hashvalue nuevo
	node_l *n=list_pop_first_node(&response_pool_free);

	if(response_pool_free==NULL)
	{	fprintf(stderr, "pool response vacio\n");
		exit(-1);
	}
	//Lo mete en el pool de usados
	list_prepend_node(&response_pool_used,n);
	
	memset(n->data, 0, sizeof(response)); //Resetear response

	gottenResponses++;

	return  (n->data); //retorna el hashvalue
	
}

// node_l *response_search(node_l **list, tcp_seq seq, int *number){

// 	node_l *n;
// 	*number = 0;

// 	//ASSERT
// 	assert(!(list==NULL));//if(list==NULL) print_backtrace("response_search list==NULL");

// 	//primero de la lista
// 	n = list_get_first_node(list);

// 	while(n != NULL) {
// 		response *res = (response *) n->data;
// 		if(res->ack == seq)
// 			return n;
		   
// 		n = list_get_next_node(list, n);
// 		*number += 1;
// 	}

// 	return NULL;

// }

void releaseResponse(response * f)
{
	node_l *n=list_pop_first_node(&response_pool_used);
	n->data=(void*)f;
	list_prepend_node(&response_pool_free,n);
	gottenResponses--;
}

void freeResponsePool(void)
{
	node_l *n=NULL;
	while(response_pool_free!=NULL)
	{
		n=list_pop_first_node(&response_pool_free);
		FREE(n);
	}

	while(response_pool_used!=NULL)
	{
		n=list_pop_first_node(&response_pool_used);
		FREE(n);
	}

	FREE(responses);
}

void fillResponse(packet_info *packet, response *res){
	strncpy(res->response_msg, packet->response_msg, RESP_MSG_SIZE);
	res->response_msg[RESP_MSG_SIZE-1] = 0;
	res->op = packet->op;
	res->responseCode = packet->responseCode;
	// res->seq = packet->tcp->th_seq;
	// res->ack = packet->tcp->th_ack;
	res->ts = packet->ts;
	return;
}
