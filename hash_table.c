//TABLA HASH
#include "hash_table.h"

#include "tools.h"
extern process_info *processing;

#define ACTIVE_CELLS_LIST_SIZE 1000000
collision_list **active_cells = NULL;
uint32_t current_active_cells = -1;
collision_list *tmp_cell = NULL;

collision_list *event_table = NULL; 
uint32_t elements = 0;

void free_event_table(){
	int i;
	for(i=0; i<EVENT_TABLE_SIZE; i++){
		FREE(event_table[i].events);
	}
	FREE(event_table);
}

// void remove_active_cell(collision_list **cell){
// 	long i;
// 	for(i=0; i<(*cell)->size; i++){
// 		(*cell)->events[i] = 0;
// 	}
// 	memcpy(&tmp_cell, &active_cells[current_active_cells], sizeof(collision_list*));
// 	memcpy(&active_cells[current_active_cells], cell, sizeof(collision_list*));
// 	memcpy(cell, &tmp_cell, sizeof(collision_list*));
// 	for(i=0; i<tmp_cell->size; i++){
// 		tmp_cell->events[i] = 0;
// 	}
// 	current_active_cells--;
// }

// void add_active_cell(collision_list **cell){
// 	current_active_cells++;
// 	active_cells[current_active_cells] = *cell;
// }

void alloc_event_table(){
	// active_cells = (collision_list**) calloc(ACTIVE_CELLS_LIST_SIZE, sizeof(collision_list*));
	event_table = (collision_list*) calloc(EVENT_TABLE_SIZE, sizeof(collision_list));
	int i;
	for(i=0; i<EVENT_TABLE_SIZE; i++){
		event_table[i].events = (http_event***) calloc(COLLISION_SIZE, sizeof(http_event**));
		event_table[i].size = COLLISION_SIZE;
	}

}

//PRIVATE
int comp_hash_key(hash_key *key_a, hash_key *key_b){
	if(key_a == NULL || key_b == NULL){
        return -1;
    }

    if( (key_a->ip_src == key_b->ip_src) &&
        (key_a->ip_dst == key_b->ip_dst) &&
        (key_a->port_src == key_b->port_src) &&
        (key_a->port_dst == key_b->port_dst)
    ){
        return 1;
    }

    return 0;
}

//PRIVATE
uint32_t calc_index(hash_key *key){
	return (key->ip_src ^ key->ip_dst ^ key->port_src ^ key->port_dst ^ key->ack_seq) % EVENT_TABLE_SIZE;
}

//PRIVATE
http_event** find_event_on_table(uint32_t index, hash_key *key){
	collision_list *cell = &(event_table[index]);
	int i;
	for(i=0; i<cell->size; i++){
		if(cell->events[i]==0){ //EMPTY ELEMENT OF THE LIST
			continue; //JUMP TO NEXT ITERATION
		}
		http_event **event = cell->events[i];
		if(comp_hash_key(&(*event)->key, key) == 1){ //FOUND IT
			return cell->events[i];
		}
	}
	return NULL; //EVENT DOES NOT EXIST
}

int remove_event_from_table(hash_key *key){
	//CHECK IF ANOTHER EVENT WITH THE SAME KEY AND INFO EXISTS
	uint32_t index = calc_index(key);
	collision_list *cell = &event_table[index];
	int i;
	for(i=0; i<cell->size; i++){
		if(cell->events[i]==0){ //EMPTY ELEMENT OF THE LIST
			continue; //JUMP TO NEXT ITERATION
		}
		http_event **event = cell->events[i];
		if(comp_hash_key(&(*event)->key, key) == 1){ //FOUND IT
			push_http_event(event); //BACK TO THE POOL
			elements--;
			// cell->used--;
			cell->events[i] = 0; //EMPTY ELEMENT OF THE LIST
			return 0;
		}
	}

	fprintf(stderr, "ERROR REMOVING ELEMENT\n");

	return -1; //EVENT NOT FOUND
}

http_event** get_event_from_table(hash_key *key){
	//CHECK IF ANOTHER EVENT WITH THE SAME KEY AND INFO EXISTS
	uint32_t index = calc_index(key);
	http_event** event = find_event_on_table(index, key);
	if(event != NULL){
		return event;
	}

	//ADDS THE EVENT IN CASE IT DOES NOT EXIST YET	
	collision_list *cell = &event_table[index];
	long i;
	struct timespec diff_req, diff_res;
	for(i=0; i<cell->size; i++){
		if(cell->events[i]!=0){
			http_event** event = cell->events[i];
			diff_req = tsSubtract(processing->last_packet, (*event)->ts_req);
			diff_res = tsSubtract(processing->last_packet, (*event)->ts_res);
			if(labs(diff_req.tv_sec) > 60 || labs(diff_res.tv_sec) > 60){
				push_http_event(event); //BACK TO THE POOL
				elements--;
				cell->events[i] = 0; //EMPTY ELEMENT OF THE LIST
			}
		}

		if(cell->events[i] == 0){ //EMPTY ELEMENT OF THE LIST
			cell->events[i] = pop_http_event(); //TAKE ELEMENT FROM POOL
			elements++;
			http_event** event = cell->events[i];
			memset(*event, 0, sizeof(http_event));
			(*event)->status = EMPTY;
			(*event)->key.ip_src   = key->ip_src;   
			(*event)->key.ip_dst   = key->ip_dst;   
			(*event)->key.port_src = key->port_src; 
			(*event)->key.port_dst = key->port_dst; 
			(*event)->key.ack_seq  = key->ack_seq;  
			return cell->events[i];
		}
	}

	// //EVENT LIST OF THE CELL IS FULL !
	
	
	for(i=0; i<cell->size; i++){
		if(cell->events[i] != 0){
			http_event** event = cell->events[i];
			diff_req = tsSubtract(processing->last_packet, (*event)->ts_req);
			diff_res = tsSubtract(processing->last_packet, (*event)->ts_res);
			if(labs(diff_req.tv_sec) > 60 || labs(diff_res.tv_sec) > 60){
				push_http_event(event); //BACK TO THE POOL
				elements--;
				// cell->used--;
				cell->events[i] = 0; //EMPTY ELEMENT OF THE LIST
			}
			// fprintf(stderr, "DIFF: %ld.%09ld\n", diff.tv_sec, diff.tv_nsec);
		}
	}

	fprintf(stderr, "REALLOC!! %"PRIu32"\n", elements);
	//REALLOC
	long prev_size = cell->size;
	cell->size *= 4;
	if(cell->size < 60000){
		cell->events = (http_event***) realloc(cell->events, cell->size * sizeof(http_event**));
		if(cell->events == NULL){
			fprintf(stderr, "REALLOC FAILED\n");
		}
		for(i=prev_size-1; i<cell->size; i++){
			cell->events[i] = 0;
		}
	}else{
		cell->size = prev_size;
		fprintf(stderr, "MAX SIZE REACHED\n");
	}
	
	struct timeval aux_exec;
  	struct timeval elapsed;
  	gettimeofday(&aux_exec, NULL);  
  	timersub(&aux_exec, &processing->start, &elapsed);
  	if(elapsed.tv_sec > 0)
		fprintf(stderr, "EVENT LIST OF THE CELL IS FULL ! ELEMENTS: %"PRIu32" PACKETS: %ld ELAPSED: %ld PPS: %ld\n", elements, processing->packets, elapsed.tv_sec, processing->packets/elapsed.tv_sec);

	for(i=0; i<cell->size; i++){
		if(cell->events[i] == 0){ //EMPTY ELEMENT OF THE LIST
			cell->events[i] = pop_http_event(); //TAKE ELEMENT FROM POOL
			elements++;
			// cell->used++;
			http_event** event = cell->events[i];
			(*event)->status = EMPTY;
			(*event)->key.ip_src   = key->ip_src;   
			(*event)->key.ip_dst   = key->ip_dst;   
			(*event)->key.port_src = key->port_src; 
			(*event)->key.port_dst = key->port_dst; 
			(*event)->key.ack_seq  = key->ack_seq;  
			return cell->events[i];
		}
	}

	return NULL;
}