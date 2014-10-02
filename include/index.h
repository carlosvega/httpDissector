#ifndef _index
#define _index
#include <stdio.h>
#include "tools.h"
void write_to_index_with_ts(long int position, struct timespec ts);
void write_to_index(long int position);
#endif