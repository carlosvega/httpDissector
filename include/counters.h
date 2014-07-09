#ifndef _counters
#define _counters

#include "http.h"

void increment_rtx_counter(unsigned long add);
unsigned long long get_total_rtx();
double get_rtx_ratio();

void increment_total_removed_requests(unsigned long add);

unsigned long long get_total_removed_requests();

void increment_total_responses();

double get_requests_without_response_lost_ratio();
double get_responses_without_request_ratio();

unsigned long long get_total_responses();

//total requests
void increment_total_requests();

unsigned long long get_total_requests();

//total connexions
void increment_total_connexions();

unsigned long long get_total_connexions();

//inserts
void increment_inserts();

void decrement_inserts();

unsigned long long get_inserts();

//transactions
void increment_transactions();

unsigned long long get_transactions();

//lost
void increment_lost();

unsigned long long get_lost();

//no cases
void increment_no_cases();

unsigned long long get_no_cases();


//total out_of_order
void increment_total_out_of_order();

unsigned long long get_total_out_of_order();

//total req_node
void increment_total_req_node();

unsigned long long get_total_req_node();

//active
void decrement_active_requests();

void increment_active_requests();

unsigned long long get_active_requests();

//patch
void increment_patch_requests();

unsigned long long get_patch_requests();

//options
void increment_options_requests();

unsigned long long get_options_requests();

//connect
void increment_connect_requests();

unsigned long long get_connect_requests();


//delete
void increment_delete_requests();

unsigned long long get_delete_requests();

//trace
void increment_trace_requests();

unsigned long long get_trace_requests();

//put
void increment_put_requests();

unsigned long long get_put_requests();

//head
void increment_head_requests();

unsigned long long get_head_requests();

//GET
void increment_get_requests();

unsigned long long get_get_requests();

//POST
void increment_post_requests();

unsigned long long get_post_requests();

void decrement_request_counter(http_op h);
void increment_request_counter(http_op h);

#endif