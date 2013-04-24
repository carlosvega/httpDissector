#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "tslist.h"

void init_list(hash_value *hashvalue){
	hashvalue->n_request = 0;
	hashvalue->n_response = 0;
	hashvalue->deleted_nodes = 0;
	hashvalue->list = (pair *) malloc(1*sizeof(pair));
	hashvalue->list->request = NULL;
	hashvalue->list->response = NULL;
	hashvalue->list->next = NULL;
    hashvalue->last = hashvalue->list;
}

void free_node_list(pair *list){

	if(list == NULL)
		return;

	free(list->request->url);
	free(list->request);
	free(list->response);
	free_node_list(list->next);
	free(list);

}

void free_tslist(hash_value *hashvalue){
	
	if(hashvalue == NULL){
		return;
	}

	free_node_list(hashvalue->list);	

	return;
}

//The pair to remove must be the first of the list.
//And will do because the first request to be satisfied is the first one.
int remove_first_node(hash_value *hashvalue){

	if(hashvalue == NULL){
		return -1;
	}

	if(hashvalue->list == NULL){
		return -1;
	}


	pair *p = hashvalue->list;

	hashvalue->list = p->next;
	free(p->request->url);
	free(p->request);
	free(p->response);
	free(p);
	hashvalue->n_request--;
	hashvalue->n_response--;

	//ERA EL UNICO PAR
	if(hashvalue->list == NULL){
		return 2;
	}

	return 0;
}

void add_tsnode_get(hash_value *hashvalue, packet_info *pkt){
	if(hashvalue == NULL || pkt == NULL)
		return;
	
	//IR AL ULTIMO
	pair *list = hashvalue->last;

	list->next = (pair *) calloc(sizeof(pair), 1);
	list->request = pkt;
	list->response = NULL;
}

void add_tsnode_res(hash_value *hashvalue, packet_info *pkt){
	if(hashvalue == NULL || pkt == NULL)
		return;

	pair *list = hashvalue->list;

	//IR AL ULTIMO SIN RESPONSE
	while(list->next != NULL && list->response != NULL){
	 	list = list->next;
	}

	list->response = pkt;
}