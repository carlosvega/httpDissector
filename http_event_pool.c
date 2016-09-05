#include "http_event_pool.h"

http_event **pool_http_event_pointers = NULL;
http_event  *pool_http_event_objects = NULL; 
http_event  *tmp_http_event = NULL; //USED TO SWAP ELEMENTS
int last_http_event = -1; //POSITION OF THE LAST ELEMENT POPED

unsigned long get_used_http_event_elements(){
	return last_http_event;
}

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
	long p;
	for(p=0; p<HTTP_EVENT_POOL_SIZE; p++){
		pool_http_event_pointers[p] = &pool_http_event_objects[p];
		pool_http_event_objects[p].parent = p;
	}
}

http_event* pop_http_event(){
	last_http_event++;
	if(last_http_event >= HTTP_EVENT_POOL_SIZE){
		fprintf(stderr, "FULL HTTP_EVENT_POOL\n");
		exit(-10);
		return NULL;
	}
	return pool_http_event_pointers[last_http_event];
}

void push_http_event(http_event *element){
	//SWAP CHILDRENS !
	//			   # 				<-- last_http_event	(last_used)
	//    [*] [*] [*] [ ] [ ]       <-- pool_http_event_pointers
    //     |   |   |
	//     V   V   V
	//     e   e   e   ·   ·		<-- pool_http_event_objects
	//     0   1   2   3   4
 	//     
	//     Example: pushing the element e1 back to the pool
	//     the last element is 2
	//     tell 2's pointer its new children is e1
	//     tell 2's element its new parent is p1
	//     tell 1's pointer its new children is e2
	//     tell 1's element its new parent is p2
	//     decrease last_http_event and clean e1
	//     
	//     Result 
	//			#                <-- last_http_event  (last_used)
	//	   [*] [*] [ ] [ ] [ ]   <-- pool_http_event_pointers
 	//	    |    ⧹  /
 	//      |     X
 	//	    V    / ⧹             <-- p1 points to e2; p2 points to e1
 	//	    e   ·   e   ·   ·	 <-- pool_http_event_objects
 	//	    0   1   2   3   4
	//

	//Get parents (pointer) location  
	unsigned long element_position = element->parent; 
	memset(element, 0, sizeof(http_event)); 
	memset(&element, 0, sizeof(element)); //CLEAN element //CORREGIR. ESTO PONE element a 0x0 no borra *element
	unsigned long last_position    = last_http_event;

	//Get childrens
	http_event *push_element = pool_http_event_pointers[element_position];
	http_event *last_element = pool_http_event_pointers[last_position];

	//UPDATE CHILDREN's PARENTS
	push_element->parent = last_position;
	last_element->parent = element_position;

	//UPDATE PARENTS's CHILDRENS
	pool_http_event_pointers[element_position] = last_element;
	pool_http_event_pointers[last_position]    = push_element;


	last_http_event--;
}
