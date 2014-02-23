#include "counters.h"

//REQUEST STATS
static unsigned long long get_requests = 0;
static unsigned long long post_requests = 0;
static unsigned long long head_requests = 0;
static unsigned long long put_requests = 0;
static unsigned long long trace_requests = 0;
static unsigned long long delete_requests = 0;
static unsigned long long options_requests = 0;
static unsigned long long patch_requests = 0;

static unsigned long long active_requests = 0;
static unsigned long long total_connexions = 0;
static unsigned long long total_req_node = 0;
static unsigned long long total_out_of_order = 0;

static unsigned long long total_removed_requests = 0;
static unsigned long long total_requests = 0;
static unsigned long long total_responses = 0;

static unsigned long long no_cases = 0;

static unsigned long long lost = 0;
static unsigned long transactions = 0;
static unsigned long long inserts = 0;

double get_responses_without_request_ratio(){
	if(lost == 0 || total_responses == 0){
		return 0;
	}

	long double a = lost;
	long double b = total_responses;

	return ((double) (a/(a+b))*100);
}

double get_requests_without_response_lost_ratio(){
	if(total_removed_requests == 0 || total_requests == 0){
		return 0;
	}

	long double a = total_removed_requests;
	long double b = total_requests;

	return ((double) (a/(a+b))*100);
}

void increment_total_removed_requests(unsigned long add){
	total_removed_requests+=add;
}

unsigned long long get_total_removed_requests(){
	return total_removed_requests;
}

//increment requests
void increment_total_requests(){
	total_requests++;
}

unsigned long long get_total_requests(){
	return total_requests;
}

//increment responses
void increment_total_responses(){
	total_responses++;
}

//total responses
unsigned long long get_total_responses(){
	return total_responses;
}

//increment connexions
void increment_total_connexions(){
	total_connexions++;
}

unsigned long long get_total_connexions(){
	return total_connexions;
}

//inserts
void increment_inserts(){
	inserts++;
}

void decrement_inserts(){
	inserts--;
}

unsigned long long get_inserts(){
	return inserts;
}

//transactions
void increment_transactions(){
	transactions++;
}

unsigned long long get_transactions(){
	return transactions;
}

//lost
void increment_lost(){
	lost++;
}

unsigned long long get_lost(){
	return lost;
}

//no cases
void increment_no_cases(){
	no_cases++;
}

unsigned long long get_no_cases(){
	return no_cases;
}


//total out_of_order
void increment_total_out_of_order(){
	total_out_of_order++;
}

unsigned long long get_total_out_of_order(){
	return total_out_of_order;
}

//total req_node
void increment_total_req_node(){
	total_req_node++;
}

unsigned long long get_total_req_node(){
	return total_req_node;
}

//active
void decrement_active_requests(){
	active_requests--;
}

void increment_active_requests(){
	active_requests++;
}

unsigned long long get_active_requests(){
	return active_requests;
}

//patch
void increment_patch_requests(){
	patch_requests++;
}

unsigned long long get_patch_requests(){
	return patch_requests;
}

//options
void increment_options_requests(){
	options_requests++;
}

unsigned long long get_options_requests(){
	return options_requests;
}


//delete
void increment_delete_requests(){
	delete_requests++;
}

unsigned long long get_delete_requests(){
	return delete_requests;
}

//trace
void increment_trace_requests(){
	trace_requests++;
}

unsigned long long get_trace_requests(){
	return trace_requests;
}

//put
void increment_put_requests(){
	put_requests++;
}

unsigned long long get_put_requests(){
	return put_requests;
}

//head
void increment_head_requests(){
	head_requests++;
}

unsigned long long get_head_requests(){
	return head_requests;
}

//GET
void increment_get_requests(){
	get_requests++;
}

unsigned long long get_get_requests(){
	return get_requests;
}

//POST
void increment_post_requests(){
	post_requests++;
}

unsigned long long get_post_requests(){
	return post_requests;
}