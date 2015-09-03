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

float pool_nodes_used_ratio(){
    return list_size(&nodel_pool_used) / ((float) MAX_POOL_NODE);
}

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
        n = n->next;
    }
}

node_l *list_get_last_node(node_l **list){

    assert(list!=NULL);

    if(*list == NULL){
        return NULL;
    }else{
        return ((*list)->prev);
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

    node_l *first=*list;

    if(first == NULL) { //Si la lista esta vacia
        node->prev = NULL;
        node->next = NULL;
        *list = node;
    } else { //Si no esta vacia

        //Solo un elemento
        if(first->prev == NULL && first->next == NULL){
            first->prev = node;
            first->next = node;
            node->next = first;
            node->prev = first;
        }else{
            assert(first->prev != NULL && first->next != NULL);
            node_l *last = first->prev;
            
            last->next = node;
            node->prev = last;
            node->next = first;
            first->prev = node;
        }
        
        *list = node;
        
    }
}

void list_append_node(node_l **list,
                        node_l  *node){

    //ASSERT
    assert(!(node==NULL));

    node_l *first = *list;
    if(first == NULL) { //Si la lista esta vacia
        node->prev = NULL;
        node->next = NULL;
        *list = node;
    } else { //Si no esta vacia

        //Solo un elemento
        if(first->prev == NULL && first->next == NULL){
            node->prev = first;
            node->next = first; //Porque node es el ultimo
            first->next = node;
            first->prev = node;
        }else{
            assert(first->prev != NULL && first->next != NULL);
            node_l *last = first->prev;
            last->next = node;
            node->prev = last;
            first->prev = node;
            node->next = first;

        }
    }
}

int list_size(node_l **list){

    assert(list!=NULL);

    int s = 0;
    node_l *n, *first = NULL;

    first = list_get_first_node(list);
    n = first;

    while(n != NULL){
        s++;
        n = n->next;
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

node_l * list_search(node_l *first, node_l *node_to_find, int cmp(void *, void *))
{
    node_l *n, *prev=NULL;

    //ASSERT
    assert(node_to_find!=NULL);

    //primero de la lista
    n = first;

    while(n!=NULL && n != prev) {
        __builtin_prefetch (n->next);
        if(cmp(n->data, node_to_find->data)==0)
            return n;
        
        prev = n;
        n = n->next;
        if(n==first){
            break;
        }
    }

    return NULL;
}

void list_unlink(node_l **list,
                 node_l  *node){

    //ASSERT
    assert(!(list==NULL));
    assert(!(node==NULL));

    if(node->next == NULL && node->prev == NULL) { //si la lista tiene 1 elemento
        *list = NULL;                       //lista a null
    } else {                                //sino
        assert(node->next != NULL && node->prev != NULL);

        node->prev->next = node->next;
        node->next->prev = node->prev;

        if(*list == node)           //si el que sacamos es el primero de la lista
            *list = node->next;     //ahora el primero es el siguiente
    
        //Si la lista se queda con solo un elemento
        node_l *first = *list;
        if(first->next == first && first->prev == first){
            first->next = NULL;
            first->prev = NULL;
        }

    }

    node->next = NULL; // NULL de los punteros primero 
    node->prev = NULL; // y siguiente del que sacamos
    
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
    size_t i=0;
    node_l *n=NULL;
    nl=malloc(sizeof(node_l)*MAX_POOL_NODE);

    if(nl == NULL){
        fprintf(stderr, "Execute the program on a host with enought memory. MAX_POOL_NODE: %d\n", MAX_POOL_NODE);
    }

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
    nodo->prev = NULL;
    nodo->next = NULL;

    nodel_aux=n->data;
    
}

void releaseNodel(node_l* f)
{

    //ASSERT
    assert(!(f==NULL));//if(f==NULL) print_backtrace("releaseNodel f==NULL");

    node_l *n=list_pop_first_node(&nodel_pool_used); // Saca nodo del pool de usados
    n->data=(void*)f;                                // 
    list_prepend_node(&nodel_pool_free,n);           // Anade al pool de libres


}

void freeNodelPool(void)
{
    node_l *n=NULL;
    int i=0;
    while(nodel_pool_free!=NULL)
    {
        i = i+1;
        n=list_pop_first_node(&nodel_pool_free);
        FREE(n);
    }

    while(nodel_pool_used!=NULL)
    {
        n=list_pop_first_node(&nodel_pool_used);
        FREE(n);
    }


    FREE(nl);
}
