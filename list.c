/*  Copyright (c) 2006-2008, Philip Busch <broesel@studcs.uni-sb.de>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

extern node_l static_node;

extern node_l *nodel_aux;
node_l *nodel_pool_free=NULL;
node_l *nodel_pool_used=NULL;


node_l *list_get_first_node(node_l **list)
{

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_get_first_node list==NULL");

	return(*list);
}

void list_foreach(node_l **list, void func(void *)){
	node_l *n;

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_foreach list==NULL");

	n = list_get_first_node(list);

	while(n != NULL) {
		func(n->data);
		n = list_get_next_node(list, n);
	}
}


node_l *list_get_last_node(node_l **list)
{

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_get_last_node list==NULL");

	if(*list == NULL) {
		fprintf(stderr, "empty list when getting last node\n");
		return(NULL);
	} else {
		if((*list)->prev == NULL){
			node_l *aux = (*list)->next;
			fprintf(stderr, "next nodes when prev = NULL: ");
			while(aux!=NULL && aux != (*list)){
				fprintf(stderr, "|, ");
				aux = aux->next;
			}
			fprintf(stderr, "\n");
		}
		return((*list)->prev);
	}
}


node_l *list_alloc_node(void *data)
{
	node_l *n = NULL;

	if((n = malloc(sizeof(node_l))) != NULL) {
		n->data = data;
	}

	return(n);
}

void list_alloc_node_no_malloc(void *data)
{
	
	static_node.data = data;
	
}

//Anade el nodo al principio
void list_prepend_node(node_l **list,
                       node_l  *node)
{

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_prepend_node list==NULL");

	//ASSERT
	assert(!(node==NULL));//if(node==NULL) print_backtrace("list_prepend_node node==NULL");

	node_l *here=*list;

	if(*list == NULL) { //Si la lista esta vacia
		node->prev = node;
		node->next = node;
		*list = node;
	} else { //Si no esta vacia

		//ASSERT
		assert(!(here==NULL));//if(here==NULL) print_backtrace("list_prepend_node here==NULL");
		assert(!(here->prev==NULL));//if(here->prev==NULL) print_backtrace("list_prepend_node here->prev==NULL");
		assert(!(here->next==NULL));

		node->prev = here->prev;
		node->next = here;
		here->prev = node;
		node->prev->next = node;

		if(here == *list) {
			*list = node;
		}
	}
}


//Anade el nodo al final
void list_append_node(node_l **list,
                    	node_l  *node)
{

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_append_node list==NULL");
	assert(!(node==NULL));//if(node==NULL) print_backtrace("list_append_node node==NULL");

	// assert(node->next == node->prev);

	node_l *here=*list;
	if(*list == NULL) { //Si la lista esta vacia
		node->prev = node;
		node->next = node;
		*list = node;
	} else { //Si no esta vacia
		//ASSERT
		assert(!(here==NULL));//if(here==NULL) print_backtrace("list_append_node here==NULL");
		assert(!(here->next==NULL));//if(here->next==NULL) print_backtrace("list_append_node here->next==NULL");
		assert(!(here->prev==NULL));//if(here->prev==NULL) print_backtrace("list_append_node here->prev==NULL");

		node_l *last = here->prev; //El ultimo es el anterior del primero
		last->next = node; //El siguiente al ultimo es el nuevo
		node->prev = last; //El anterior al nuevo es el que era ultimo
		node->next = here; //El siguiente al nuevo es el primero
		here->prev = node; //El anterior al primero es el nuevo
	}
}

// int list_size(node_l **list)   
// {   
//     int s = 0;   
//     node_l *n;   
   
//     assert(list != NULL);   
   
//     n = *list;   
   
//     while(n != NULL) {   
//         n = list_get_next_node(list, n);   
//         s++;   
//     }   
   
//     return(s);     
// }

int list_size(node_l **list){

	assert(list!=NULL);

	int s = 0;
	node_l *n, *first = NULL;

	first = list_get_first_node(list);
	n = first;

	while(n != NULL){
		s++;
		n = list_get_next_node(list, n);
		if(n==first){
			break;
		}
	}

	return s;

} 

int list_is_empty(node_l **list)
{

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_is_empty list==NULL");

	return(*list == NULL);
}

node_l * list_search(node_l **list, node_l *node_to_find, int cmp(void *, void *))
{
	node_l *n;

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_search list==NULL");
	assert(!(node_to_find==NULL));//if(node_to_find==NULL) print_backtrace("list_search node_to_find==NULL");

	//primero de la lista
	n = list_get_first_node(list);

	while(n != NULL) {
		if(cmp(n->data,node_to_find->data)==0)
			return n;
		   
		n = list_get_next_node(list, n);
	}

	return NULL;
}

void list_unlink(node_l **list,
                 node_l  *node)
{

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_unlink list==NULL");
	assert(!(node==NULL));//if(node==NULL) print_backtrace("list_unlink node==NULL");

	if(node->next == node) { 				//si la lista tiene 1 elemento
		assert(node->next == node->prev);
		*list = NULL; 		 				//lista a null
	} else { 				 				//sino
		assert(node->prev != NULL);
		if(node->prev!=NULL) 				//si el anterior del que sacamos no es null
			node->prev->next = node->next;  //el siguiente del anterior ahora apunta al siguiente del que hemos sacado
		
		assert(node->next != NULL);
		if(node->next!=NULL) 				//si el siguiente del que sacamos no es null
			node->next->prev = node->prev;  //el anterior al siguiente ahora apunta al anterior del que hemos sacado

		if(*list == node) 	 				//si el que sacamos es el primero de la lista
			*list = node->next; 			//ahora el primero es el siguiente
	}

	node->next = node; //
	node->prev = node; //NULL de los punteros primero y siguiente del que sacamos
	
	//REPAIR LIST IF BROKEN
	// if((*list)!=NULL && (*list)->prev == NULL){
	// 	node_l *aux = (*list);
	// 	fprintf(stderr, "FIXING LIST aux->next: %s\n", aux->next == NULL? "NULL" : "!NULL");
	// 	while(aux->next != NULL && aux != (*list)){
	// 		aux = aux->next;
	// 	}
	// 	(*list)->prev = aux;
	// 	aux->next = (*list);
	// }

}

node_l *list_pop_first_node(node_l **list)
{
	node_l *n;

	//ASSERT
	assert(!(list==NULL));//if(list==NULL) print_backtrace("list_pop_first_node list==NULL");

	n = list_get_first_node(list);

	if(n != NULL)
		list_unlink(list, n);

	return(n);
}

node_l *nl;

void allocNodelPool(void)
{
	int i=0;
	node_l *n=NULL;
	nl=malloc(sizeof(node_l)*MAX_POOL_NODE);

	//ASSERT
	assert(!(nl==NULL));//if(nl==NULL) print_backtrace("allocNodelPool nl==NULL");

	for(i=0;i<MAX_POOL_NODE;i++)
	{
		n=list_alloc_node(nl+i);
		list_prepend_node(&nodel_pool_free,n);
	}

}


void getNodel(void)
{

	node_l *n=list_pop_first_node(&nodel_pool_free);
	if(nodel_pool_free==NULL)
		fprintf(stderr, "pool Nodos vacío\n");
	list_prepend_node(&nodel_pool_used,n);

	//ASSERT
	assert(!(n==NULL));//if(n==NULL) print_backtrace("getNodel n==NULL");

	node_l *nodo = (node_l*) n->data;
	nodo->prev = nodo;
	nodo->next = nodo;

	nodel_aux=n->data;
	
}

void releaseNodel(node_l* f)
{

	//ASSERT
	assert(!(f==NULL));//if(f==NULL) print_backtrace("releaseNodel f==NULL");

	node_l *n=list_pop_first_node(&nodel_pool_used); // Saca nodo del pool de usados
	n->data=(void*)f;								 // 
	list_prepend_node(&nodel_pool_free,n);			 // Anade al pool de libres


}

void freeNodelPool(void)
{
	node_l *n=NULL;
	while(nodel_pool_free!=NULL)
	{
		n=list_pop_first_node(&nodel_pool_free);
		free(n);
	}

	while(nodel_pool_used!=NULL)
	{
		n=list_pop_first_node(&nodel_pool_used);
		free(n);
	}
	free(nl);
}
