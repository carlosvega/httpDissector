#include "http_event_pool.h"

http_event **pool_http_event_pointers = NULL;
http_event *pool_http_event_objects = NULL; 
http_event *tmp_http_event = NULL; //USED TO SWAP ELEMENTS
int last_http_event = -1; //POSITION OF THE LAST ELEMENT POPED

void free_http_event_pool(){
	FREE(pool_http_event_pointers);
	FREE(pool_http_event_objects);
	tmp_http_event = NULL;
	last_http_event = -1;
}

void alloc_http_event_pool(){
	//ALLOC
	pool_http_event_pointers = (http_event**) calloc(HTTP_EVENT_POOL_SIZE, sizeof(http_event*));
	pool_http_event_objects  = (http_event*) calloc(HTTP_EVENT_POOL_SIZE, sizeof(http_event));
	//ALLOC TEMP VARIABLE FOR SWAP
	tmp_http_event = (http_event*) calloc(1, sizeof(http_event));
	//INIT 
	int p;
	for(p=0; p<HTTP_EVENT_POOL_SIZE; p++){
		pool_http_event_pointers[p] = &pool_http_event_objects[p];
	}
}

http_event** pop_http_event(){
	last_http_event++;
	if(last_http_event > HTTP_EVENT_POOL_SIZE){
		fprintf(stderr, "FULL HTTP_EVENT_POOL\n");
		exit(-10);
		return NULL;
	}
	return &pool_http_event_pointers[last_http_event];
}

void push_http_event(http_event **element){
	memset(*element, 0, sizeof(http_event)); //CLEAN
	memcpy(&tmp_http_event, &pool_http_event_pointers[last_http_event], sizeof(http_event*));
	memcpy(&pool_http_event_pointers[last_http_event], element, sizeof(http_event*));
	memcpy(element, &tmp_http_event, sizeof(http_event*));

	// memset(&tmp_http_event, 0, sizeof(0)); //CLEAN TMP_http_event

	last_http_event--;
}