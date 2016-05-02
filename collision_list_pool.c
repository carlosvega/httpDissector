#include "collision_list_pool.h"

collision_list **pool_collision_list_pointers = NULL;
collision_list  *pool_collision_list_objects  = NULL;
collision_list  **tmp_collision_list = NULL; //USED TO SWAP ELEMENTS
unsigned long last_collision_list = -1; //POSITION OF THE LAST ELEMENT POPED

unsigned long get_used(){
	return last_collision_list;
}

void free_collision_list_pool(){
	FREE(pool_collision_list_pointers);
	FREE(pool_collision_list_objects);
	tmp_collision_list = NULL;
	last_collision_list = -1;
}

void alloc_collision_list_pool(){
	//ALLOC
	pool_collision_list_pointers = (collision_list **) calloc(COLLISION_LIST_POOL_SIZE, sizeof(collision_list*));
	pool_collision_list_objects = (collision_list *) calloc(COLLISION_LIST_POOL_SIZE, sizeof(collision_list));
	//ALLOC TEMP VARIABLE FOR SWAP
	tmp_collision_list = (collision_list**) calloc(1, sizeof(collision_list*));
	//INIT
	unsigned long p;
	for(p=0; p<COLLISION_LIST_POOL_SIZE; p++){
		pool_collision_list_pointers[p] = &pool_collision_list_objects[p];
		pool_collision_list_objects[p].parent = p;
		// pool_collision_list_objects[p].id = p;
	}
}

collision_list* pop_collision_list(){
	last_collision_list++;
	if(last_collision_list >= COLLISION_LIST_POOL_SIZE){
		fprintf(stderr, "FULL COLLISION_LIST_POOL\n");
		exit(-11);
		return NULL;
	}
	// fprintf(stderr, "pop element.used %d\telement.a\t%lu\telement.id\t%lu\n", pool_collision_list_pointers[last_collision_list]->used, pool_collision_list_pointers[last_collision_list]->parent,
		// pool_collision_list_pointers[last_collision_list]->id);

	return pool_collision_list_pointers[last_collision_list];
}

void push_collision_list(collision_list *element){
	
	//SWAP CHILDRENS !
	//			   # 				<-- last_collision_list	(last_used)
	//    [*] [*] [*] [ ] [ ]       <-- pool_collision_list_pointers
    //     |   |   |
	//     V   V   V
	//     e   e   e   ·   ·		<-- pool_collision_list_elements
	//     0   1   2   3   4
 	//     
	//     Example: pushing the element e1 back to the pool
	//     the last element is 2
	//     tell 2's pointer its new children is e1
	//     tell 2's element its new parent is p1
	//     tell 1's pointer its new children is e2
	//     tell 1's element its new parent is p2
	//     decrease last_collision_list and clean e1
	//     
	//     Result 
	//			#                <-- last_collision_list  (last_used)
	//	   [*] [*] [ ] [ ] [ ]   <-- pool_collision_list_pointers
 	//	    |    ⧹  /
 	//      |     X
 	//	    V    / ⧹             <-- p1 points to e2; p2 points to e1
 	//	    e   ·   e   ·   ·	 <-- pool_collision_list_elements
 	//	    0   1   2   3   4
	//

	element->used = 0;
	int i;
	for(i=0; i<COLLISION_SIZE; i++){
		element->events[i] = 0;
	}

	// fprintf(stderr, "PUSH BEFORE.\telement\tused\t%d\telement\tindex\t%lu\telement\tpointer\t%p\tid\t%lu\n", 
	// 	element->used, element->parent, element, element->id);
	// fprintf(stderr, "PUSH BEFORE.\tlast\tused\t%d\tlast\tindex\t%lu\tlast\tpointer\t%p\tid\t%lu\n", 
	// 	pool_collision_list_pointers[last_collision_list]->used, pool_collision_list_pointers[last_collision_list]->parent, pool_collision_list_pointers[last_collision_list],
	// 		pool_collision_list_pointers[last_collision_list]->id);

	//Get parents (pointer) location 
	unsigned long element_position = element->parent;
	unsigned long last_position    = last_collision_list;

	//Get childrens
	collision_list *push_element = pool_collision_list_pointers[element_position];
	collision_list *last_element = pool_collision_list_pointers[last_position];

	//UPDATE CHILDREN's PARENTS
	push_element->parent = last_position;
	last_element->parent = element_position;

	// fprintf(stderr, "PUSH MIDDLE.\telement\tused\t%d\telement\tindex\t%lu\telement\tpointer\t%p\tid\t%lu\n", 
	// 	pool_collision_list_pointers[element_position]->used, pool_collision_list_pointers[element_position]->parent, pool_collision_list_pointers[element_position],
	// 		pool_collision_list_pointers[element_position]->id);
	// fprintf(stderr, "PUSH MIDDLE.\tlast\tused\t%d\tlast\tindex\t%lu\tlast\tpointer\t%p\tid\t%lu\n", 
	// 		pool_collision_list_pointers[last_collision_list]->used, pool_collision_list_pointers[last_collision_list]->parent, pool_collision_list_pointers[last_collision_list],
	// 		pool_collision_list_pointers[last_collision_list]->id);

	//UPDATE PARENTS's CHILDRENS
	pool_collision_list_pointers[element_position] = last_element;
	pool_collision_list_pointers[last_position]    = push_element;

	// fprintf(stderr, "PUSH AFTER.\telement\tused\t%d\telement\tindex\t%lu\telement\tpointer\t%p\tid\t%lu\n", 
	// 	pool_collision_list_pointers[element_position]->used, pool_collision_list_pointers[element_position]->parent, pool_collision_list_pointers[element_position],
	// 		pool_collision_list_pointers[element_position]->id);
	// fprintf(stderr, "PUSH AFTER.\tlast\tused\t%d\tlast\tindex\t%lu\tlast\tpointer\t%p\tid\t%lu\n", 
	// 	pool_collision_list_pointers[last_collision_list]->used, pool_collision_list_pointers[last_collision_list]->parent, pool_collision_list_pointers[last_collision_list],
	// 		pool_collision_list_pointers[last_collision_list]->id);
	
	last_collision_list--;

}















