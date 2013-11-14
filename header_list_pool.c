#include "header_list_pool.h"

node_l *header_pool_free=NULL;
node_l *header_pool_used=NULL;

collision_list *header_lists;

void allocHeaderListPool(void)
{
	int i=0;
	node_l *n=NULL;
	header_lists=calloc(HEADER_LIST_POOL_SIZE, sizeof(collision_list));
	assert(header_lists!=NULL);
	for(i=0;i<HEADER_LIST_POOL_SIZE;i++)
	{
		n=list_alloc_node(header_lists+i);
		list_prepend_node(&header_pool_free, n);
	}
}

collision_list * getHeaderList(void)
{

	//Obtiene nodo del pool con el hashvalue nuevo
	node_l *n=list_pop_first_node(&header_pool_free);

	if(header_pool_free==NULL)
	{	fprintf(stderr, "pool header vacio\n");
		exit(-1);
	}
	//Lo mete en el pool de usados
	list_prepend_node(&header_pool_used,n);

	memset(n->data, 0, sizeof(collision_list));				
	//Resetear request

	return  (n->data); //retorna el hashvalue
	
}

void releaseHeaderList(collision_list * f)
{
	node_l *n=list_pop_first_node(&header_pool_used);
	n->data=(void*)f;
	list_prepend_node(&header_pool_free,n);
}

void freeHeaderListPool(void)
{
	node_l *n=NULL;
	while(header_pool_free!=NULL)
	{
		n=list_pop_first_node(&header_pool_free);
		FREE(n);
	}

	while(header_pool_used!=NULL)
	{
		n=list_pop_first_node(&header_pool_used);
		FREE(n);
	}

	FREE(header_lists);
}