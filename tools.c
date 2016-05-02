#include "tools.h"
#include <execinfo.h>

#define ALPHABET_SIZE (1 << CHAR_BIT)
#define LIST_OF_FILES 10

#define FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

void print_backtrace(char *err){
	fprintf(stderr, "%s\n", err);

	void* callstack[256];
	int i, frames = backtrace(callstack, 256);
	char** strs = backtrace_symbols(callstack, frames);
	for (i = 0; i < frames; ++i) {
		fprintf(stderr, "%s\n", strs[i]);
	}
	free(strs);
	exit(0);
}

static void compute_prefix(const char* str, size_t size, int result[size]) {
	size_t q;
	int k;
	result[0] = 0;
	
	k = 0;
	for (q = 1; q < size; q++) {
		while (k > 0 && str[k] != str[q])
			k = result[k-1];
		
		if (str[k] == str[q])
			k++;
		result[q] = k;
	}
}

static void prepare_badcharacter_heuristic(const char *str, size_t size,
	int result[ALPHABET_SIZE]) {
	
	size_t i;
	
	for (i = 0; i < ALPHABET_SIZE; i++)
		result[i] = -1;
	
	for (i = 0; i < size; i++)
		result[(size_t) str[i]] = i;
}

void prepare_goodsuffix_heuristic(const char *normal, size_t size,
	int result[size + 1]) {
	
	char *left = (char *) normal;
	char *right = left + size;
	char reversed[size+1];
	char *tmp = reversed + size;
	size_t i;
	
 /* reverse string */
	*tmp = 0;
	while (left < right)
		*(--tmp) = *(left++);
	
	int prefix_normal[size];
	int prefix_reversed[size];
	
	compute_prefix(normal, size, prefix_normal);
	compute_prefix(reversed, size, prefix_reversed);
	
	for (i = 0; i <= size; i++) {
		result[i] = size - prefix_normal[size-1];
	}
	
	for (i = 0; i < size; i++) {
		const int j = size - prefix_reversed[i];
		const int k = i - prefix_reversed[i]+1;
		
		if (result[j] > k)
			result[j] = k;
	}
}
/*
 * Boyer-Moore search algorithm
 */
 const char *boyermoore_search(const char *haystack, const char *needle) {
 /*
 * Calc string sizes
 */
 size_t needle_len, haystack_len;
 needle_len = strlen(needle);
 haystack_len = strlen(haystack);
 
 /*
 * Simple checks
 */
 if(haystack_len == 0)
 	return NULL;
 if(needle_len == 0)
 	return NULL;
 if(needle_len > haystack_len)
 	return NULL;
 /*
 * Initialize heuristics
 */
 int badcharacter[ALPHABET_SIZE];
 int goodsuffix[needle_len+1];
 
 prepare_badcharacter_heuristic(needle, needle_len, badcharacter);
 prepare_goodsuffix_heuristic(needle, needle_len, goodsuffix);
 
 /*
 * Boyer-Moore search
 */
 size_t s = 0;
 while(s <= (haystack_len - needle_len))
 {
 	size_t j = needle_len;
 	while(j > 0 && needle[j-1] == haystack[s+j-1])
 		j--;
 	
 	if(j > 0)
 	{
 		int k = badcharacter[(size_t) haystack[s+j-1]];
 		int m;
 		if(k < (int)j && (m = j-k-1) > goodsuffix[j])
 			s+= m;
 		else
 			s+= goodsuffix[j];
 	}
 	else
 	{
 		return haystack + s;
 	}
 }

 /* not found */
 return NULL;
}

struct timespec timeval_to_timespec(struct timeval ts){
	struct timespec t;
	t.tv_sec = ts.tv_sec;
	t.tv_nsec = ts.tv_usec*1000;
	return t;
}

char *timeval_to_char(struct timespec ts){

	// char time_buf[64] = {0};
	char *ret = (char *) calloc(sizeof(char), 128);

	// time_t nowtime;
	// nowtime = ts.tv_sec;

	//UTC TIME
	//struct tm *my_time = gmtime(&nowtime);
	//strftime(time_buf, 64, "%Y-%m-%d %H:%M:%S", my_time);
	snprintf(ret, 128, "%ld.%09ld", (long) ts.tv_sec, (long) ts.tv_nsec);
	
	return ret;
}

// char *hash_key(const packet_info *pktinfo){

// 	char *buf = NULL;

// 	if(pktinfo->request == 1){
// 		buf = (char*) calloc(45, sizeof(char));
// 		if(buf == NULL) 
// 			return NULL;
// 		else
// 			snprintf(buf, 45, "%s%i%s%i", pktinfo->ip_addr_src, pktinfo->port_src, pktinfo->ip_addr_dst, pktinfo->port_dst);
// 	}else if(pktinfo->request == 0){
// 		buf = (char*) calloc(45, sizeof(char));
// 		if(buf == NULL) 
// 			return NULL;
// 		else
// 			snprintf(buf, 45, "%s%i%s%i", pktinfo->ip_addr_dst, pktinfo->port_dst, pktinfo->ip_addr_src, pktinfo->port_src);
// 	}

// 	return buf;
// }

/**
	-1  if TIME1 < TIME2
	0  if TIME1 = TIME2
	+1  if TIME1 > TIME2
**/
int  tsCompare (struct  timespec  time1, struct  timespec  time2){

    if (time1.tv_sec < time2.tv_sec)
        return (-1) ;				/* Less than. */
    else if (time1.tv_sec > time2.tv_sec)
        return (1) ;				/* Greater than. */
    else if (time1.tv_nsec < time2.tv_nsec)
        return (-1) ;				/* Less than. */
    else if (time1.tv_nsec > time2.tv_nsec)
        return (1) ;				/* Greater than. */
    else
        return (0) ;				/* Equal. */

}

struct  timespec  tsSubtract2 (struct  timespec  t1, struct  timespec  t2){

	struct  timespec  diff ;

	if ((t1.tv_sec < t2.tv_sec) || ((t1.tv_sec == t2.tv_sec) && (t1.tv_nsec < t2.tv_nsec))){
		diff = tsSubtract(t2, t1);
		diff.tv_sec = diff.tv_sec*-1;
	}else{
		diff = tsSubtract(t1, t2);
	}

    return (diff) ;

}

struct  timespec  tsSubtract (struct  timespec  t1, struct  timespec  t2){

	struct  timespec  diff ;

    // T1 <= T2?
	if ((t1.tv_sec < t2.tv_sec) || ((t1.tv_sec == t2.tv_sec) && (t1.tv_nsec <= t2.tv_nsec))) {
		diff.tv_sec = diff.tv_nsec = 0 ;
    } else {						// T1 > T2
    	diff.tv_sec = t1.tv_sec - t2.tv_sec ;
    	if (t1.tv_nsec < t2.tv_nsec) {
    		diff.tv_nsec = t1.tv_nsec + 1000000000L - t2.tv_nsec ;
            diff.tv_sec-- ;				//
        } else {
        	diff.tv_nsec = t1.tv_nsec - t2.tv_nsec ;
        }
    }

    return (diff) ;

}

double  tsFloat (struct  timespec  time){

    return ((double) time.tv_sec + (time.tv_nsec / 1000000000.0));

}

struct  timespec  tsAdd (struct  timespec  time1, struct  timespec  time2){    

    struct  timespec  result;

	/* Add the two times together. */

    result.tv_sec = time1.tv_sec + time2.tv_sec ;
    result.tv_nsec = time1.tv_nsec + time2.tv_nsec ;
    
    if (result.tv_nsec >= 1000000000L) {		/* Carry? */
        result.tv_sec++ ;  result.tv_nsec = result.tv_nsec - 1000000000L ;
    }

    return (result) ;

}

char ** parse_list_of_files(char *filename, unsigned int *n_files){

	FILE *list_of_files = NULL;
	char **files = NULL;
	size_t len = 0;
	ssize_t read;
	char *line = NULL;
	unsigned int number_of_files = 0;
	unsigned int allocs = 1;

	list_of_files = fopen(filename, "r");
	if(list_of_files == NULL){
		fprintf(stderr, "ERROR TRYING TO OPEN THE LIST OF FILES\n");
		return NULL;
	}

	
	files = (char **) malloc(LIST_OF_FILES*sizeof(char*));
	if(files == NULL){
		return NULL;
	}

	while((read = getline(&line, &len, list_of_files)) !=-1 ){
		line[read-1] = '\0'; //Removes ending \n
		
		if(number_of_files == LIST_OF_FILES*allocs){
			allocs++;
			files = (char **) realloc(files, LIST_OF_FILES*allocs*sizeof(char*));
		}

		files[number_of_files] = line;
		line = NULL;
		number_of_files++;
	}

	FREE(line);

	fclose(list_of_files);
	*n_files = number_of_files;

	return files;
}
