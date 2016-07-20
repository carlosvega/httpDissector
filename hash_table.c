//TABLA HASH
#include "hash_table.h"

#include "tools.h"
extern process_info *processing;

collision_list **event_table = NULL; 
uint32_t elements = 0;

void free_event_table(){
	FREE(event_table);
}

void alloc_event_table(){
	event_table = (collision_list**) calloc(EVENT_TABLE_SIZE, sizeof(collision_list*));
}

//PRIVATE
int comp_hash_key(hash_key *key_a, hash_key *key_b){
	if(key_a == NULL || key_b == NULL){
        return -1;
    }

    if( (key_a->ip_src == key_b->ip_src) &&
        (key_a->ip_dst == key_b->ip_dst) &&
        (key_a->port_src == key_b->port_src) &&
        (key_a->port_dst == key_b->port_dst) && 
        (key_a->ack_seq == key_b->ack_seq)
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
http_event* find_event_on_table(uint32_t index, hash_key *key){
	collision_list *cell = event_table[index];

	//CELL NOT USED
	if(cell == 0 || cell == NULL){ //NULL
		return NULL; 
	}

	//LOOP THROUGH COLLISIONS IN CELL
	int i;
	for(i=0; i<COLLISION_SIZE; i++){
		if(cell->events[i]!=0){ //NON EMPTY ELEMENT OF THE LIST
			http_event *event = cell->events[i];
			if(comp_hash_key(&event->key, key) == 1){ //FOUND IT
				return cell->events[i]; //RETURN ELEMENT
			}
		}
	}

	return NULL; //EVENT DOES NOT EXIST
}

int remove_event_from_table(hash_key *key){
	//CHECK IF ANOTHER EVENT WITH THE SAME KEY AND INFO EXISTS

	uint32_t index = calc_index(key);
	collision_list *cell = event_table[index];

	if(cell == 0 || cell == NULL){
		fprintf(stderr, "ERROR REMOVING ELEMENT 1 - %"PRIu32"\n", key->ack_seq);
		return -1;
	}

	int i;
	for(i=0; i<COLLISION_SIZE; i++){
		if(cell->events[i]!=0){ //NON EMPTY ELEMENT OF THE LIST
			http_event *event = cell->events[i];
			if(comp_hash_key(&event->key, key) == 1){ //FOUND IT
				push_http_event(event); //BACK TO THE POOL
				elements--;
				cell->used-=1;
				cell->events[i] = 0; //EMPTY ELEMENT OF THE LIST
				if(cell->used == 0){
					push_collision_list(cell);
					event_table[index] = 0;
				}
				return 0;
			}	
		}
	}

	fprintf(stderr, "ERROR REMOVING ELEMENT - %"PRIu32"\n", key->ack_seq);

	return -1; //EVENT NOT FOUND
}

http_event* get_event_from_table(hash_key *key){
	//CALC INDEX IN TABLE
	uint32_t index = calc_index(key);
	
	//GET CELL
	collision_list *cell = event_table[index];
	if(cell != 0 && cell != NULL){
		//CHECK IF ANOTHER EVENT WITH THE SAME KEY AND INFO EXISTS
		http_event* event = find_event_on_table(index, key);
		if(event != NULL){
			return event;
		}
	}else{
		//IF NO CELL, GET ONE
		cell = pop_collision_list();
		event_table[index] = cell;
		if(cell->used != 0){
			fprintf(stderr, "THIS MUST NOT HAPPEN !!!!!!!\n"); //REMOVE AFTER CHECKING EVERYTHING IS STABLE
		}
	}
	
	long i;
	// struct timespec diff_req = {0}, diff_res = {0};
	for(i=0; i<COLLISION_SIZE; i++){
		// if(cell->events[i]!=0){ //NON EMPTY ELEMENT
		// 	//CHECK IF HAS TO BE REMOVED (gc will do for us in future) 
		// 	http_event** event = cell->events[i];
		// 	diff_req.tv_sec = 0;
		// 	diff_req.tv_nsec = 0;
		// 	diff_res.tv_sec = 0;
		// 	diff_res.tv_nsec = 0;
		// 	if((*event)->ts_req.tv_sec != 0){
		// 		diff_req = tsSubtract2(processing->last_packet, (*event)->ts_req);
		// 	}
		// 	if((*event)->ts_res.tv_sec != 0){
		// 		diff_res = tsSubtract2(processing->last_packet, (*event)->ts_res);
		// 	}			
		// 	if(labs(diff_req.tv_sec) > 60 || labs(diff_res.tv_sec) > 60){
		// 		fprintf(stderr, "ELEMENTS: %ld Processing: %ld ts_req: %ld.%09ld ts_res: %ld.%09ld last_packet: %ld.%09ld diff_req: %ld.%09ld diff_res: %ld.%09ld\n", elements, processing->packets, (*event)->ts_req.tv_sec, (*event)->ts_req.tv_nsec, (*event)->ts_res.tv_sec, (*event)->ts_res.tv_nsec, processing->last_packet.tv_sec, processing->last_packet.tv_nsec, diff_req.tv_sec, diff_req.tv_nsec, diff_res.tv_sec, diff_res.tv_nsec);
		// 		push_http_event(event); //BACK TO THE POOL
		// 		elements--;
		// 		cell->events[i] = 0; //EMPTY ELEMENT OF THE LIST
		// 		cell->used--;
		// 		if(cell->used == 0){
		// 			push_collision_list(cell);
		// 			event_table[index] = 0;
		// 		}
		// 	}
		// }

		//TODO: RECOLECTOR DE BASURA QUE RECORRA LA LISTA DE ACTIVOS DEL POOL DE COLISIONES
		//IMPRIMIR EVENTOS ZOMBIES Y VER QUE LES PASA, SI TIENEN PAREJA O NO

		if(cell->events[i] == 0){ //EMPTY ELEMENT OF THE LIST
			cell->events[i] = pop_http_event(); //TAKE ELEMENT FROM POOL
			cell->used+=1;
			elements++;

			http_event* event = cell->events[i];

			event->status = EMPTY;
			event->key.ip_src   = key->ip_src;   
			event->key.ip_dst   = key->ip_dst;   
			event->key.port_src = key->port_src; 
			event->key.port_dst = key->port_dst; 
			event->key.ack_seq  = key->ack_seq; 
			return cell->events[i];
		}
	}

	// for(i=0; i<COLLISION_SIZE; i++){
	// 	if(cell->events[i]!=0){ //NON EMPTY ELEMENT
	// 		//CHECK IF HAS TO BE REMOVED (gc will do for us in future) 
	// 		http_event** event = cell->events[i];
	// 		if((*event)->ts_req.tv_sec == 0 && (*event)->ts_res.tv_sec == 0 && (*event)->ts_req.tv_nsec == 0 && (*event)->ts_res.tv_nsec == 0){
	// 			fprintf(stderr, "BOTH ARE ZERO ! O.o  %"PRIu32" \n", (*event)->key.ack_seq);
	// 			print_http_event(event, stderr);
	// 			fprintf(stderr, "END BOTH - index %"PRIu32" - status %d | used: %d (i %ld)\n", index, (*event)->status, cell->used, i);
	// 		}
	// 		diff_req.tv_sec = 0;
	// 		diff_req.tv_nsec = 0;
	// 		diff_res.tv_sec = 0;
	// 		diff_res.tv_nsec = 0;
	// 		if((*event)->ts_req.tv_sec != 0){
	// 			diff_req = tsSubtract2(processing->last_packet, (*event)->ts_req);
	// 		}
	// 		if((*event)->ts_res.tv_sec != 0){
	// 			diff_res = tsSubtract2(processing->last_packet, (*event)->ts_res);
	// 		}		
	// 		if(labs(diff_req.tv_sec) > 60 || labs(diff_res.tv_sec) > 60){
	// 			fprintf(stderr, "index %"PRIu32" (u %d) - ELEMENTS: %u Processing: %ld ts_req: %ld.%09ld ts_res: %ld.%09ld last_packet: %ld.%09ld diff_req: %ld.%09ld diff_res: %ld.%09ld\n", index, cell->used, elements, processing->packets, (*event)->ts_req.tv_sec, (*event)->ts_req.tv_nsec, (*event)->ts_res.tv_sec, (*event)->ts_res.tv_nsec, processing->last_packet.tv_sec, processing->last_packet.tv_nsec, diff_req.tv_sec, diff_req.tv_nsec, diff_res.tv_sec, diff_res.tv_nsec);
	// 			push_http_event(event); //BACK TO THE POOL
	// 			elements--;
	// 			cell->events[i] = 0; //EMPTY ELEMENT OF THE LIST
	// 			cell->used-=1;
	// 			if(cell->used == 0){
	// 				push_collision_list(cell);
	// 				event_table[index] = 0;
	// 			}
	// 		}
	// 	}
	// }

	// for(i=0; i<COLLISION_SIZE; i++){
	// 	if(cell->events[i] == 0){ //EMPTY ELEMENT OF THE LIST
	// 		cell->events[i] = pop_http_event(); //TAKE ELEMENT FROM POOL
	// 		cell->used+=1;
	// 		elements++;

	// 		http_event** event = cell->events[i];
	// 		memset(*event, 0, sizeof(http_event));

	// 		(*event)->status = EMPTY;
	// 		(*event)->key.ip_src   = key->ip_src;   
	// 		(*event)->key.ip_dst   = key->ip_dst;   
	// 		(*event)->key.port_src = key->port_src; 
	// 		(*event)->key.port_dst = key->port_dst; 
	// 		(*event)->key.ack_seq  = key->ack_seq; 
	// 		return cell->events[i];
	// 	}
	// }

	//struct timeval aux_exec;
  	//struct timeval elapsed;
  	//gettimeofday(&aux_exec, NULL);  
  	//timersub(&aux_exec, &processing->start, &elapsed);
  	if(cell->used >= COLLISION_SIZE-1){
		fprintf(stderr, "EVENT LIST OF THE CELL IS FULL ! - index %"PRIu32" (u %d) - ELEMENTS: %"PRIu32" PACKETS: %"PRIu32"\n", index, cell->used, elements, processing->packets);
//		fprintf(stderr, "EVENT LIST OF THE CELL IS FULL ! - index %"PRIu32" (u %d) - ELEMENTS: %"PRIu32" PACKETS: %"PRIu32" ELAPSED: %ld PPS: %ld USED_COL_POOL: %ld\n", index, cell->used, elements, processing->packets, elapsed.tv_sec, elapsed.tv_sec > 0 ? processing->packets/elapsed.tv_sec : 0, get_used_collision_list_elements());
  	}else{
  		fprintf(stderr, "NULL WITHOUT FULL LIST OF THE CELL\n");
	}

	return NULL;
}

//ANOTHER EVENT IS SUPPOSED TO EXIST WITH THE SAME KEY
http_event* create_collision_on_table(hash_key *key){
	//CALC INDEX IN TABLE
	uint32_t index = calc_index(key);

	collision_list *cell = event_table[index];

	//CELL NOT USED
	if(cell == 0 || cell == NULL){ //NULL
		return NULL; 
	}

	//LOOP THROUGH COLLISIONS IN CELL
	int i;
	for(i=0; i<COLLISION_SIZE; i++){
		if(cell->events[i]!=0){ //NON EMPTY ELEMENT OF THE LIST
			http_event *event = cell->events[i];
			if(comp_hash_key(&event->key, key) == 1){ //FOUND IT, GET NEXT !
				if(i==COLLISION_SIZE-1){ //NO SPACE AVAILABLE
					return NULL;
				}

				if(cell->events[i+1]==0){ //EMPTY ELEMENT AFTERWARDS
					cell->events[i+1] = pop_http_event(); //TAKE ELEMENT FROM POOL
					cell->used+=1;
					elements++;

					http_event* event = cell->events[i+1];
					event->status = EMPTY;
					event->key.ip_src   = key->ip_src;   
					event->key.ip_dst   = key->ip_dst;   
					event->key.port_src = key->port_src; 
					event->key.port_dst = key->port_dst; 
					event->key.ack_seq  = key->ack_seq; 

					return cell->events[i+1]; //RETURN ELEMENT
				}
			}
		}
	}

	return NULL; //EVENT DOES NOT EXIST 
}
